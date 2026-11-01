//! A module used to handle TLS/SSL connection for implementations of RTSPS

use rustls_pki_types::ServerName;
use tokio_rustls::{
    rustls, rustls::RootCertStore, rustls::client::ClientConfig, rustls::crypto::CryptoProvider,
};
use url::Host;

use std::sync::Arc;

#[cfg(feature = "ring")]
fn default_provider() -> Arc<CryptoProvider> {
    Arc::new(tokio_rustls::rustls::crypto::ring::default_provider())
}

#[cfg(feature = "aws-lc-rs")]
fn default_provider() -> Arc<CryptoProvider> {
    Arc::new(tokio_rustls::rustls::crypto::aws_lc_rs::default_provider())
}

#[cfg(all(feature = "aws-lc-rs", feature = "ring"))]
compile_error!("You must enable only one of aws-lc-rs or ring as a tokio crypto provider'.");

#[cfg(not(any(feature = "ring", feature = "aws-lc-rs")))]
compile_error!("You must enable a crypto provider in order to use rustls either ring or aws-lc-rs");

pub(crate) fn default_client_config() -> Arc<ClientConfig> {
    let mut root_store = RootCertStore::empty();

    // 2. Populate it with Mozilla's trusted root certificates from webpki-roots
    root_store.roots = webpki_roots::TLS_SERVER_ROOTS
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    let provider = default_provider();

    Arc::new(
        ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("failed to select protocol versions")
            // Provide the root certificates (uses WebPkiServerVerifier internally)
            .with_root_certificates(root_store)
            // Specify that the client will not present a client certificate
            .with_no_client_auth(),
    )
}

pub(crate) fn servername_from_host(
    host: &Host<&str>,
) -> Result<ServerName<'static>, std::io::Error> {
    Ok(match host {
        Host::Domain(h) => ServerName::try_from(h.to_string()).map_err(std::io::Error::other)?,
        Host::Ipv4(h) => ServerName::from(*h),
        Host::Ipv6(h) => ServerName::from(*h),
    })
}

#[cfg(feature = "dangerous")]
pub mod dangerous {
    use super::*;

    #[derive(Debug, Clone)]
    pub struct AcceptSelfSigned(Arc<rustls::crypto::CryptoProvider>);

    impl AcceptSelfSigned {
        pub fn client_config(self) -> Result<rustls::ClientConfig, rustls::Error> {
            let provider = self.0.clone();
            let config = rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()?
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(self))
                .with_no_client_auth();
            Ok(config)
        }
    }

    impl Default for AcceptSelfSigned {
        fn default() -> Self {
            let provider = default_provider();
            Self(provider)
        }
    }

    impl rustls::client::danger::ServerCertVerifier for AcceptSelfSigned {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls_pki_types::CertificateDer<'_>,
            _intermediates: &[rustls_pki_types::CertificateDer<'_>],
            _server_name: &rustls_pki_types::ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls_pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &rustls_pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            // Skipped on purpose: webpki cannot parse the v1 cert to extract the key.
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &rustls_pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }
}
