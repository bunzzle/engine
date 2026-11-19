use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use dns::Name;
use rt::{TcpStream, timeout};
use tls::{Connector, Verify};

use crate::https;
use crate::mx::{self, Addresses, Dns};

const UPLOAD: Duration = Duration::from_secs(60);
const READ: usize = 4096;
const HEAD: usize = 8 * 1024;
pub(crate) const MEDIA: &str = "application/tlsrpt+gzip";

pub(crate) struct Target {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) path: String,
}

pub(crate) fn target(uri: &str) -> Option<Target> {
    let rest = uri.strip_prefix("https://")?;
    let (authority, path) = match rest.find(['/', '?']) {
        Some(at) => (&rest[..at], &rest[at..]),
        None => (rest, "/"),
    };
    let path = if path.starts_with('?') {
        format!("/{path}")
    } else {
        path.to_owned()
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, port.parse().ok()?),
        None => (authority, 443),
    };
    let valid =
        !host.is_empty() && Name::parse(host).is_ok() && path.bytes().all(|b| b.is_ascii_graphic());
    valid.then(|| Target {
        host: host.to_ascii_lowercase(),
        port,
        path,
    })
}

pub(crate) async fn upload<D: Dns>(
    dns: &D,
    tls: &Connector,
    egress: IpAddr,
    uri: &str,
    body: &[u8],
) -> bool {
    let Some(target) = target(uri) else {
        return false;
    };
    timeout(UPLOAD, send(dns, tls, egress, &target, body))
        .await
        .unwrap_or(false)
}

async fn send<D: Dns>(
    dns: &D,
    tls: &Connector,
    egress: IpAddr,
    target: &Target,
    body: &[u8],
) -> bool {
    let Ok(name) = Name::parse(&target.host) else {
        return false;
    };
    let Addresses::Found { ips, .. } = mx::addresses(dns, &name, egress.is_ipv6()).await else {
        return false;
    };
    let request = https::post(&target.host, &target.path, MEDIA, body);
    for ip in ips {
        let Ok(io) = TcpStream::connect_from(egress, SocketAddr::new(ip, target.port)).await else {
            continue;
        };
        let Ok(mut stream) = tls.connect(io, &target.host, Verify::WebPki).await else {
            continue;
        };
        if stream.write_all(&request).await.is_err() {
            continue;
        }
        let mut bytes = Vec::new();
        let mut buf = [0; READ];
        while bytes.len() < HEAD && !bytes.windows(2).any(|w| w == b"\r\n") {
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => bytes.extend_from_slice(&buf[..n]),
            }
        }
        return https::status(&bytes).is_some_and(|code| (200..300).contains(&code));
    }
    false
}

#[cfg(test)]
mod tests {
    use super::target;

    #[test]
    fn reads_report_targets() {
        let one = target("https://r.example/v1/tls?x=1").expect("target");
        assert_eq!(
            (one.host.as_str(), one.port, one.path.as_str()),
            ("r.example", 443, "/v1/tls?x=1")
        );
        let port = target("https://R.example:8443").expect("target");
        assert_eq!(
            (port.host.as_str(), port.port, port.path.as_str()),
            ("r.example", 8443, "/")
        );
        let query = target("https://r.example?x=1").expect("target");
        assert_eq!(query.path, "/?x=1");
        for bad in [
            "http://r.example/",
            "https://",
            "https://r.example:x/",
            "https://r ex/",
            "https://r.example/a b",
        ] {
            assert!(target(bad).is_none(), "{bad}");
        }
    }
}
