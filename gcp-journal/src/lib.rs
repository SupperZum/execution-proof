//! A private, independently owned Cloud Storage journal.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use reqwest::{blocking::Client, redirect::Policy, StatusCode, Url};
use serde::{Deserialize, Serialize};
use std::{io::Read, time::Duration};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

const STORAGE: &str = "https://storage.googleapis.com";
const METADATA: &str =
    "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token";
const MAX_WIRE: usize = 128 << 10;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Unavailable,
    Conflict,
}

pub struct Entry {
    pub first: bool,
    pub payload: Vec<u8>,
}

pub trait PublicationJournal {
    fn publish(
        &self,
        stage: &str,
        identity: &[u8],
        binding: &[u8],
        payload: &[u8],
        window: Option<(u64, u64)>,
    ) -> Result<Entry, Error>;

    fn read(
        &self,
        stage: &str,
        identity: &[u8],
        binding: &[u8],
        window: Option<(u64, u64)>,
    ) -> Result<Option<Vec<u8>>, Error>;
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    key: String,
    binding: String,
    payload: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ObjectMetadata {
    bucket: String,
    name: String,
    generation: String,
    time_finalized: Option<String>,
}

pub struct Journal {
    client: Client,
    bucket: String,
    endpoint: Url,
    token: String,
}

impl Journal {
    /// Use the operator-configured bucket and the runtime's attached identity.
    pub fn connect(bucket: &str) -> Result<Self, Error> {
        if !(3..=63).contains(&bucket.len())
            || !bucket
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            || bucket.starts_with('-')
            || bucket.ends_with('-')
        {
            return Err(Error::Unavailable);
        }
        let client = Client::builder()
            .no_proxy()
            .redirect(Policy::none())
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|_| Error::Unavailable)?;
        let response = client
            .get(METADATA)
            .header("Metadata-Flavor", "Google")
            .send()
            .map_err(|_| Error::Unavailable)?;
        if response.status() != StatusCode::OK
            || response
                .headers()
                .get("Metadata-Flavor")
                .and_then(|v| v.to_str().ok())
                != Some("Google")
        {
            return Err(Error::Unavailable);
        }
        #[derive(Deserialize)]
        struct Credential {
            access_token: String,
        }
        let credential: Credential =
            serde_json::from_slice(&body(response)?).map_err(|_| Error::Unavailable)?;
        if credential.access_token.is_empty() {
            return Err(Error::Unavailable);
        }
        Ok(Self {
            client,
            bucket: bucket.into(),
            endpoint: Url::parse(STORAGE).map_err(|_| Error::Unavailable)?,
            token: credential.access_token,
        })
    }
}

impl PublicationJournal for Journal {
    fn publish(
        &self,
        stage: &str,
        identity: &[u8],
        binding: &[u8],
        payload: &[u8],
        window: Option<(u64, u64)>,
    ) -> Result<Entry, Error> {
        let name = key(stage, identity);
        let record = Record {
            key: name.clone(),
            binding: hash(binding),
            payload: URL_SAFE_NO_PAD.encode(payload),
        };
        let wire = serde_json::to_vec(&record).map_err(|_| Error::Unavailable)?;
        if wire.len() > MAX_WIRE || payload.is_empty() {
            return Err(Error::Unavailable);
        }
        let mut upload = self.endpoint.clone();
        upload
            .path_segments_mut()
            .map_err(|_| Error::Unavailable)?
            .extend(["upload", "storage", "v1", "b", &self.bucket, "o"]);
        upload.query_pairs_mut().extend_pairs([
            ("uploadType", "media"),
            ("name", &name),
            ("ifGenerationMatch", "0"),
        ]);
        let first = self
            .client
            .post(upload)
            .bearer_auth(&self.token)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(wire)
            .send()
            .is_ok_and(|reply| reply.status().is_success());

        // The response can disappear after the conditional write committed.
        let saved = self
            .read_key(&name, &record.binding, window)?
            .ok_or(Error::Unavailable)?;
        if first && saved != payload {
            return Err(Error::Conflict);
        }
        Ok(Entry {
            first,
            payload: saved,
        })
    }

    fn read(
        &self,
        stage: &str,
        identity: &[u8],
        binding: &[u8],
        window: Option<(u64, u64)>,
    ) -> Result<Option<Vec<u8>>, Error> {
        self.read_key(&key(stage, identity), &hash(binding), window)
    }
}

impl Journal {
    fn read_key(
        &self,
        name: &str,
        binding: &str,
        window: Option<(u64, u64)>,
    ) -> Result<Option<Vec<u8>>, Error> {
        let mut url = self.endpoint.clone();
        url.path_segments_mut()
            .map_err(|_| Error::Unavailable)?
            .extend(["storage", "v1", "b", &self.bucket, "o", name]);
        let mut metadata_url = url.clone();
        metadata_url
            .query_pairs_mut()
            .extend_pairs([("alt", "json"), ("projection", "noAcl")]);
        let response = self
            .client
            .get(metadata_url)
            .bearer_auth(&self.token)
            .send()
            .map_err(|_| Error::Unavailable)?;
        match response.status() {
            StatusCode::NOT_FOUND => return Ok(None),
            StatusCode::OK => (),
            _ => return Err(Error::Unavailable),
        }
        let metadata: ObjectMetadata =
            serde_json::from_slice(&body(response)?).map_err(|_| Error::Unavailable)?;
        if metadata.bucket != self.bucket
            || metadata.name != name
            || metadata
                .generation
                .parse::<u64>()
                .ok()
                .filter(|g| *g > 0)
                .is_none()
        {
            return Err(Error::Unavailable);
        }
        if let Some((not_before, expires)) = window {
            let time = OffsetDateTime::parse(
                metadata
                    .time_finalized
                    .as_deref()
                    .ok_or(Error::Unavailable)?,
                &Rfc3339,
            )
            .map_err(|_| Error::Unavailable)?;
            let finalized = u64::try_from(time.unix_timestamp()).map_err(|_| Error::Unavailable)?;
            if !(not_before..expires).contains(&finalized) {
                return Err(Error::Conflict);
            }
        }
        url.query_pairs_mut().extend_pairs([
            ("alt", "media"),
            ("ifGenerationMatch", &metadata.generation),
        ]);
        let response = self
            .client
            .get(url)
            .bearer_auth(&self.token)
            .send()
            .map_err(|_| Error::Unavailable)?;
        if response.status() != StatusCode::OK {
            return Err(Error::Unavailable);
        }
        let record: Record =
            serde_json::from_slice(&body(response)?).map_err(|_| Error::Unavailable)?;
        if record.key != name || record.binding != binding {
            return Err(Error::Conflict);
        }
        let payload = URL_SAFE_NO_PAD
            .decode(record.payload)
            .map_err(|_| Error::Unavailable)?;
        if payload.is_empty() {
            return Err(Error::Unavailable);
        }
        Ok(Some(payload))
    }
}

fn key(stage: &str, identity: &[u8]) -> String {
    format!("a04-v2/{stage}/{}", hash(identity))
}

fn hash(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(ring::digest::digest(&ring::digest::SHA384, bytes))
}

fn body(response: reqwest::blocking::Response) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    response
        .take((MAX_WIRE + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Unavailable)?;
    if bytes.len() > MAX_WIRE {
        return Err(Error::Unavailable);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests;
