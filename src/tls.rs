//! A module used to handle TLS/SSL connection for implementations of RTSPS

use rustls_pki_types::ServerName;
use url::Host;

pub(crate) fn servername_from_host(
    host: &Host<&str>,
) -> Result<ServerName<'static>, std::io::Error> {
    Ok(match host {
        Host::Domain(h) => ServerName::try_from(h.to_string()).map_err(std::io::Error::other)?,
        Host::Ipv4(h) => ServerName::from(*h),
        Host::Ipv6(h) => ServerName::from(*h),
    })
}
