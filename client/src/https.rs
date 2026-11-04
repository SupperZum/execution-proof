//! Explicit HTTPS origins and fixed protocol routes, with bounded response reads.
//! No proxy, redirect, cookie jar, ambient authorization, or automatic retry.

use crate::ClientError;
use std::time::Duration;

pub const MAX_TRANSPORT_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone, Copy)]
pub enum LaunchRoute {
    Begin,
    Capture,
    ResourceChallenge,
    ResourceDecision,
    CredentialDelivery,
}

impl LaunchRoute {
    pub fn path(self) -> &'static str {
        match self {
            Self::Begin => "/kbs/launch/v1/begin",
            Self::Capture => "/kbs/launch/v1/capture",
            Self::ResourceChallenge => "/kbs/launch/v1/resource-challenge",
            Self::ResourceDecision => "/kbs/launch/v1/resource-decision",
            Self::CredentialDelivery => "/kbs/launch/v1/credential-delivery",
        }
    }
}

pub struct HttpsTransport {
    origin: reqwest::Url,
    client: reqwest::Client,
}

impl HttpsTransport {
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

    pub async fn post(&self, route: LaunchRoute, body: &[u8]) -> Result<Vec<u8>, ClientError> {
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
                HttpsTransport::new(origin),
                Err(ClientError::InvalidOrigin)
            ));
        }
        for origin in [
            "https://example.com",
            "https://example.com/",
            "https://example.com:8443",
        ] {
            let transport = HttpsTransport::new(origin).unwrap();
            for route in [
                LaunchRoute::Begin,
                LaunchRoute::Capture,
                LaunchRoute::ResourceChallenge,
                LaunchRoute::ResourceDecision,
                LaunchRoute::CredentialDelivery,
            ] {
                let url = transport.origin.join(route.path()).unwrap();
                assert_eq!(url.origin(), transport.origin.origin());
                assert!(url.path().starts_with("/kbs/launch/v1/"));
            }
        }
    }
}
