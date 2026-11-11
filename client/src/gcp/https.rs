//! Explicit HTTPS origins and fixed protocol routes, with bounded response reads.
//! No proxy, redirect, cookie jar, ambient authorization, or automatic retry.

use crate::ClientError;
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

pub const MAX_TRANSPORT_BYTES: usize = super::MAX_REQUEST_BYTES;

#[derive(Clone, Copy)]
pub enum GcpLaunchRoute {
    Begin,
    Capture,
    ResourceChallenge,
    ResourceDecision,
    CredentialDelivery,
}

impl GcpLaunchRoute {
    pub fn path(self) -> &'static str {
        match self {
            Self::Begin => "/kbs/launch/gcp/v2/begin",
            Self::Capture => "/kbs/launch/gcp/v2/capture",
            Self::ResourceChallenge => "/kbs/launch/gcp/v2/resource-challenge",
            Self::ResourceDecision => "/kbs/launch/gcp/v2/resource-decision",
            Self::CredentialDelivery => "/kbs/launch/gcp/v2/credential-delivery",
        }
    }
}

pub struct GcpHttpsTransport {
    origin: reqwest::Url,
    client: reqwest::Client,
}

impl GcpHttpsTransport {
    /// Constructor-selected CA roots and addresses for the closed startup path.
    /// Origin and references must already be authenticated by that owner. This
    /// creates a bounded transport, not a boot or authorization capability.
    pub fn with_trusted_roots(
        origin: &str,
        roots_pem: &[u8],
        addresses: &[SocketAddr],
    ) -> Result<Self, ClientError> {
        if origin
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control() || b == b'\\')
        {
            return Err(ClientError::InvalidOrigin);
        }
        let authority = origin
            .strip_prefix("https://")
            .ok_or(ClientError::InvalidOrigin)?;
        let authority = authority.strip_suffix('/').unwrap_or(authority);
        if authority.contains(['/', '@', '?', '#']) {
            return Err(ClientError::InvalidOrigin);
        }
        let host = authority
            .split(':')
            .next()
            .ok_or(ClientError::InvalidOrigin)?;
        if let Some((_, port)) = authority.split_once(':') {
            let parsed = port
                .parse::<u16>()
                .map_err(|_| ClientError::InvalidOrigin)?;
            if parsed == 0 || parsed.to_string() != port {
                return Err(ClientError::InvalidOrigin);
            }
        }
        if host.is_empty()
            || host.len() > 253
            || host.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            })
        {
            return Err(ClientError::InvalidOrigin);
        }
        let origin = reqwest::Url::parse(origin).map_err(|_| ClientError::InvalidOrigin)?;
        if origin.scheme() != "https"
            || origin.domain() != Some(host)
            || !origin.username().is_empty()
            || origin.password().is_some()
            || origin.query().is_some()
            || origin.fragment().is_some()
            || origin.path() != "/"
        {
            return Err(ClientError::InvalidOrigin);
        }
        let port = origin
            .port_or_known_default()
            .ok_or(ClientError::InvalidOrigin)?;
        if addresses.is_empty() || addresses.len() > 8 {
            return Err(ClientError::InvalidField);
        }
        for (index, address) in addresses.iter().enumerate() {
            let ip = match address.ip() {
                IpAddr::V6(v6) => v6
                    .to_ipv4_mapped()
                    .map(IpAddr::V4)
                    .unwrap_or(IpAddr::V6(v6)),
                ip => ip,
            };
            if address.port() != port
                || ip.is_unspecified()
                || ip.is_multicast()
                || addresses[..index].contains(address)
            {
                return Err(ClientError::InvalidField);
            }
        }
        if roots_pem.is_empty() || roots_pem.len() > 64 << 10 {
            return Err(ClientError::InvalidField);
        }
        let mut remainder =
            std::str::from_utf8(roots_pem).map_err(|_| ClientError::InvalidField)?;
        let mut count = 0usize;
        loop {
            remainder = remainder.trim_matches(|c: char| c.is_ascii_whitespace());
            if remainder.is_empty() {
                break;
            }
            let body = remainder
                .strip_prefix("-----BEGIN CERTIFICATE-----")
                .ok_or(ClientError::InvalidField)?;
            let (payload, rest) = body
                .split_once("-----END CERTIFICATE-----")
                .ok_or(ClientError::InvalidField)?;
            if !payload.bytes().all(|b| {
                b.is_ascii_alphanumeric() || b"+/=".contains(&b) || b.is_ascii_whitespace()
            }) {
                return Err(ClientError::InvalidField);
            }
            remainder = rest;
            count += 1;
            if count > 16 {
                return Err(ClientError::InvalidField);
            }
        }
        let roots = reqwest::Certificate::from_pem_bundle(roots_pem)
            .map_err(|_| ClientError::InvalidField)?;
        if count == 0 || roots.len() != count {
            return Err(ClientError::InvalidField);
        }
        let client = reqwest::Client::builder()
            .tls_backend_rustls()
            .tls_certs_only(roots)
            .tls_version_min(reqwest::tls::Version::TLS_1_3)
            .tls_sslkeylogfile(false)
            .https_only(true)
            .http1_only()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .referer(false)
            .retry(reqwest::retry::never())
            .pool_max_idle_per_host(0)
            .resolve_to_addrs(host, addresses)
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(5))
            .build()
            .map_err(|_| ClientError::Transport)?;
        Ok(Self { origin, client })
    }

    pub fn new(origin: &str) -> Result<Self, ClientError> {
        // Reject path spellings before URL normalization can erase dot segments.
        if origin
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control() || b == b'\\')
        {
            return Err(ClientError::InvalidOrigin);
        }
        let (_, authority) = origin.split_once("://").ok_or(ClientError::InvalidOrigin)?;
        if authority
            .split('/')
            .next()
            .is_some_and(|value| value.contains('@'))
        {
            return Err(ClientError::InvalidOrigin);
        }
        if authority
            .split_once('/')
            .is_some_and(|(_, path)| !path.is_empty())
        {
            return Err(ClientError::InvalidOrigin);
        }
        let origin = reqwest::Url::parse(origin).map_err(|_| ClientError::InvalidOrigin)?;
        if origin.scheme() != "https"
            || origin.host_str().is_none()
            || !origin.username().is_empty()
            || origin.password().is_some()
            || origin.query().is_some()
            || origin.fragment().is_some()
            || origin.path() != "/"
        {
            return Err(ClientError::InvalidOrigin);
        }
        let client = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .referer(false)
            .retry(reqwest::retry::never())
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(5))
            .build()
            .map_err(|_| ClientError::Transport)?;
        Ok(Self { origin, client })
    }

    pub async fn post(&self, route: GcpLaunchRoute, body: &[u8]) -> Result<Vec<u8>, ClientError> {
        if body.len() > MAX_TRANSPORT_BYTES {
            return Err(ClientError::TooLarge);
        }
        let url = self
            .origin
            .join(route.path())
            .map_err(|_| ClientError::InvalidOrigin)?;
        let mut response = self
            .client
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body.to_vec())
            .send()
            .await
            .map_err(|_| ClientError::Transport)?;
        if !response.status().is_success() {
            return Err(ClientError::HttpStatus);
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_TRANSPORT_BYTES as u64)
        {
            return Err(ClientError::TooLarge);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| ClientError::Transport)? {
            if chunk.len() > MAX_TRANSPORT_BYTES - bytes.len() {
                return Err(ClientError::TooLarge);
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }
}

#[cfg(test)]
#[path = "https/trusted_roots_tests.rs"]
mod trusted_roots_tests;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_explicit_https_origins_and_static_routes_are_supported() {
        for origin in [
            "http://example.com",
            "https://user:password@example.com",
            "https://@example.com",
            "https://example.com/path",
            "https://example.com/a/..",
            "https://example.com/%2e",
            "https://example.com?query=1",
            "https://example.com#fragment",
            "https://example.com\\",
            " https://example.com",
        ] {
            assert!(matches!(
                GcpHttpsTransport::new(origin),
                Err(ClientError::InvalidOrigin)
            ));
        }
        for origin in [
            "https://example.com",
            "https://example.com/",
            "https://example.com:8443",
        ] {
            let transport = GcpHttpsTransport::new(origin).unwrap();
            for route in [
                GcpLaunchRoute::Begin,
                GcpLaunchRoute::Capture,
                GcpLaunchRoute::ResourceChallenge,
                GcpLaunchRoute::ResourceDecision,
                GcpLaunchRoute::CredentialDelivery,
            ] {
                let url = transport.origin.join(route.path()).unwrap();
                assert_eq!(url.origin(), transport.origin.origin());
                assert!(url.path().starts_with("/kbs/launch/gcp/v2/"));
            }
        }
    }
}
