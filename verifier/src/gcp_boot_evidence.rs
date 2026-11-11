//! Bounded structural checks for the explicitly selected GCP direct-PE profile.
//!
//! Nothing here authenticates a quote, establishes measurement causality, or
//! qualifies a producer. Consumers must first authenticate these *exact* quote
//! bytes with QVL and independently approve firmware/boot/producer policy.

use crate::{hex_field, VerificationError};
use ring::digest::{digest, SHA384};
use serde::{Deserialize, Serialize};

pub const MAX_QUOTE_BYTES: usize = 512 * 1024;
pub const MAX_LOG_BYTES: usize = 1024 * 1024;
pub const MAX_EVENTS: usize = 4096;
pub const MAX_EVENT_DATA_BYTES: usize = 256 * 1024;
const SHA384_ALG: u16 = 0x000c;
const NO_ACTION: u32 = 3;
const SEPARATOR: u32 = 4;
const EFI_APP: u32 = 0x8000_0003;
const EFI_GPT: u32 = 0x8000_0006;
const EFI_ACTION: u32 = 0x8000_0007;
const CALL_APPLICATION: &[u8] = b"Calling EFI Application from Boot Option";
const EXIT_INVOCATION: &[u8] = b"Exit Boot Services Invocation";
const EXIT_SUCCESS: &[u8] = b"Exit Boot Services Returned with Success";

type Result<T> = std::result::Result<T, VerificationError>;
fn invalid(reason: &'static str) -> VerificationError {
    VerificationError::Invalid(reason)
}
fn sha384(bytes: &[u8]) -> [u8; 48] {
    let mut out = [0; 48];
    out.copy_from_slice(digest(&SHA384, bytes).as_ref());
    out
}

/// Padding is selected by trusted configuration, never inferred from the input.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuotePaddingPolicy {
    ExactFrame,
    /// Only the observed GCP TSM ABI: exactly 8000 bytes, bounded zero tail.
    GcpTsmZeroPadded8000,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcpInstanceIdentity {
    pub instance_id: u64,
    pub numerical_project_id: u64,
    pub zone: String,
}

impl GcpInstanceIdentity {
    pub fn mr_owner(&self) -> Result<[u8; 48]> {
        if self.instance_id == 0
            || self.numerical_project_id == 0
            || self.zone.is_empty()
            || self.zone.len() > 63
            || !self
                .zone
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(invalid("gcp_instance_identity"));
        }
        // GCP PZID recipe: exact key order and compact decimal JSON. Validation
        // above excludes escaping and caller-controlled JSON syntax.
        let json = format!(
            "{{\"instanceId\":{},\"numericalProjectId\":{},\"zone\":\"{}\"}}",
            self.instance_id, self.numerical_project_id, self.zone
        );
        Ok(sha384(json.as_bytes()))
    }
}

/// Independent operator inputs, never references enrolled from submitted logs.
/// Firmware authentication and PE Authenticode hashing happen outside this module.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcpBootEvidencePolicy {
    pub expected_pe_sha384: String,
    pub expected_firmware_mrtd: String,
    pub expected_instance: GcpInstanceIdentity,
    pub quote_padding: QuotePaddingPolicy,
}

impl GcpBootEvidencePolicy {
    pub fn validate(&self) -> Result<()> {
        reference(&self.expected_pe_sha384)?;
        reference(&self.expected_firmware_mrtd)?;
        self.expected_instance.mr_owner()?;
        Ok(())
    }
}

fn reference(value: &str) -> Result<[u8; 48]> {
    hex_field(value, 48)?;
    let mut result = [0; 48];
    for (out, pair) in result
        .iter_mut()
        .zip(value.as_bytes().as_chunks::<2>().0.iter())
    {
        let nibble = |b: u8| {
            if b.is_ascii_digit() {
                b - b'0'
            } else {
                b - b'a' + 10
            }
        };
        *out = nibble(pair[0]) * 16 + nibble(pair[1]);
    }
    if result == [0; 48] {
        return Err(invalid("gcp_boot_zero_reference"));
    }
    Ok(result)
}

/// Public, unauthenticated quote fields. This type is not a verified capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicQuoteFacts {
    pub quote_version: u16,
    pub mr_td: [u8; 48],
    pub mr_config_id: [u8; 48],
    pub mr_owner: [u8; 48],
    pub mr_seam: [u8; 48],
    pub td_attributes: u64,
    pub rtmrs: [[u8; 48]; 4],
    pub report_data: [u8; 64],
    pub quote_sha384: [u8; 48],
    pub declared_frame_bytes: usize,
    pub trailing_zero_padding_bytes: usize,
}

/// Predicate agreement only: there is deliberately no authorizing/verified
/// verdict, Deserialize implementation, or conversion to an execution claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StructuralBootEvidence {
    pub quote: PublicQuoteFacts,
    pub event_count: usize,
    pub extended_event_counts: [usize; 4],
    pub used_log_bytes: usize,
    pub log_sha384: [u8; 48],
    pub descriptor_sha384: [u8; 48],
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if n > self.bytes.len() - self.offset {
            return Err(invalid("gcp_evidence_truncated"));
        }
        let value = &self.bytes[self.offset..self.offset + n];
        self.offset += n;
        Ok(value)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?
            .try_into()
            .map_err(|_| invalid("gcp_evidence_width"))
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.array()?))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }
    fn end(&self) -> Result<()> {
        if self.offset != self.bytes.len() {
            Err(invalid("gcp_evidence_trailing_bytes"))
        } else {
            Ok(())
        }
    }
    fn remaining(&self) -> &'a [u8] {
        &self.bytes[self.offset..]
    }
}

/// Strict framing, not cryptographic verification. The original padded bytes
/// remain committed by quote_sha384 and must be sent unchanged to QVL.
pub fn parse_quote(quote: &[u8], padding: QuotePaddingPolicy) -> Result<PublicQuoteFacts> {
    if quote.is_empty() || quote.len() > MAX_QUOTE_BYTES {
        return Err(VerificationError::ResourceLimit("gcp_quote_size"));
    }
    let mut c = Cursor::new(quote);
    let version = c.u16()?;
    if !matches!(version, 4 | 5) || c.u16()? != 2 || c.u32()? != 0x81 || c.u32()? != 0 {
        return Err(invalid("gcp_quote_header"));
    }
    // Intel QE vendor UUID, encoded as the 16 bytes in the quote header.
    if c.take(16)?
        != [
            0x93, 0x9a, 0x72, 0x33, 0xf7, 0x9c, 0x4c, 0xa9, 0x94, 0x0a, 0x0d, 0xb3, 0x95, 0x7f,
            0x06, 0x07,
        ]
    {
        return Err(invalid("gcp_quote_vendor"));
    }
    c.take(20)?; // User data is authenticated by QVL, not a trust input here.
    let body_size = if version == 4 {
        584
    } else {
        match (c.u16()?, c.u32()?) {
            (2, 584) => 584,
            (3, 648) => 648,
            _ => return Err(invalid("gcp_quote_v5_body")),
        }
    };
    let mut body = Cursor::new(c.take(body_size)?);
    body.take(16)?; // TEE_TCB_SVN is appraised by the separate QVL policy.
    let mr_seam = body.array()?;
    body.take(48)?; // MRSIGNERSEAM
    body.take(8)?; // SEAMATTRIBUTES
    let td_attributes = body.u64()?;
    body.take(8)?; // XFAM
    let mr_td = body.array()?;
    let mr_config_id = body.array()?;
    let mr_owner = body.array()?;
    body.take(48)?; // MROWNERCONFIG
    let rtmrs = [body.array()?, body.array()?, body.array()?, body.array()?];
    let report_data = body.array()?;
    if body_size == 648 {
        body.take(64)?;
    } // TEE_TCB_SVN2/MRSERVICETD
    body.end()?;
    let signature_bytes = c.u32()? as usize;
    let mut sig = Cursor::new(c.take(signature_bytes)?);
    sig.take(128)?; // ECDSA signature and attestation public key
    if sig.u16()? != 6 {
        return Err(invalid("gcp_quote_certification_type"));
    }
    let outer_size = sig.u32()? as usize;
    let mut qe = Cursor::new(sig.take(outer_size)?);
    sig.end()?;
    qe.take(448)?; // QE report and QE signature
    let auth_size = qe.u16()? as usize;
    qe.take(auth_size)?;
    if qe.u16()? != 5 {
        return Err(invalid("gcp_quote_pck_type"));
    }
    let pck_size = qe.u32()? as usize;
    if pck_size == 0 {
        return Err(invalid("gcp_quote_empty_pck"));
    }
    qe.take(pck_size)?;
    qe.end()?;
    let declared_frame_bytes = c.offset;
    let tail = c.remaining();
    match padding {
        QuotePaddingPolicy::ExactFrame if !tail.is_empty() => {
            return Err(invalid("gcp_quote_padding"))
        }
        QuotePaddingPolicy::GcpTsmZeroPadded8000
            if quote.len() != 8000 || tail.iter().any(|b| *b != 0) =>
        {
            return Err(invalid("gcp_quote_padding"));
        }
        _ => {}
    }
    Ok(PublicQuoteFacts {
        quote_version: version,
        mr_td,
        mr_config_id,
        mr_owner,
        mr_seam,
        td_attributes,
        rtmrs,
        report_data,
        quote_sha384: sha384(quote),
        declared_frame_bytes,
        trailing_zero_padding_bytes: tail.len(),
    })
}

fn check_descriptor(table: &[u8], log_len: usize) -> Result<()> {
    if table.len() != 56 || &table[..4] != b"CCEL" {
        return Err(invalid("gcp_ccel_descriptor"));
    }
    let mut c = Cursor::new(table);
    c.take(4)?;
    if c.u32()? != 56 || c.u8()? != 1 || table.iter().fold(0u8, |s, b| s.wrapping_add(*b)) != 0 {
        return Err(invalid("gcp_ccel_acpi_checksum"));
    }
    c.take(27)?; // Rest of ACPI header
    if c.take(4)? != [2, 0, 0, 0] {
        return Err(invalid("gcp_ccel_type"));
    }
    let capacity = c.u64()?;
    let address = c.u64()?;
    if capacity == 0
        || capacity > MAX_LOG_BYTES as u64
        || capacity != log_len as u64
        || address == 0
        || address.checked_add(capacity).is_none()
    {
        return Err(invalid("gcp_ccel_capacity"));
    }
    c.end()
}

fn spec_id(data: &[u8]) -> Result<()> {
    let mut c = Cursor::new(data);
    if c.take(16)? != b"Spec ID Event03\0" || c.u32()? > 1 {
        return Err(invalid("gcp_ccel_spec_id"));
    }
    let minor = c.u8()?;
    let major = c.u8()?;
    let errata = c.u8()?;
    let uintn = c.u8()?;
    if (major, minor, errata) != (2, 0, 0)
        || !matches!(uintn, 1 | 2)
        || c.u32()? != 1
        || c.u16()? != SHA384_ALG
        || c.u16()? != 48
    {
        return Err(invalid("gcp_ccel_spec_profile"));
    }
    let vendor_len = c.u8()? as usize;
    c.take(vendor_len)?;
    c.end()
}

fn image_load(data: &[u8]) -> Result<()> {
    let mut c = Cursor::new(data);
    let location = c.u64()?;
    let length = c.u64()?;
    c.u64()?; // Link address does not provide authority.
    let path_len = c.u64()?;
    if length == 0
        || location.checked_add(length).is_none()
        || !(4..=(MAX_EVENT_DATA_BYTES - 32) as u64).contains(&path_len)
    {
        return Err(invalid("gcp_efi_image_size"));
    }
    let mut path = Cursor::new(c.take(path_len as usize)?);
    c.end()?;
    let mut count = 0;
    let mut terminated = false;
    while !path.remaining().is_empty() {
        count += 1;
        if count > 64 || terminated {
            return Err(invalid("gcp_efi_path_nodes"));
        }
        let kind = path.u8()?;
        let subtype = path.u8()?;
        let length = path.u16()? as usize;
        if length < 4 {
            return Err(invalid("gcp_efi_path_length"));
        }
        let payload = path.take(length - 4)?;
        // Closed direct GCP NVMe path. Other transports require a new profile.
        match (kind, subtype, length) {
            (2, 1, 12) | (1, 1, 6) | (3, 0x17, 16) | (4, 1, 42) => {}
            (4, 4, _) if payload.len() >= 2 && payload.len() % 2 == 0 => {
                let mut units = payload
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|b| u16::from_le_bytes([b[0], b[1]]));
                if units.next_back() != Some(0)
                    || units.clone().any(|u| u == 0)
                    || char::decode_utf16(units).any(|u| u.is_err())
                {
                    return Err(invalid("gcp_efi_file_path"));
                }
            }
            (0x7f, 1, 4) => {}
            (0x7f, 0xff, 4) => terminated = true,
            _ => return Err(invalid("gcp_efi_path_type")),
        }
    }
    if !terminated {
        return Err(invalid("gcp_efi_path_unterminated"));
    }
    Ok(())
}

#[derive(Debug)]
struct Event<'a> {
    mr: u32,
    kind: u32,
    digest: Option<[u8; 48]>,
    data: &'a [u8],
}
#[derive(Debug)]
struct Log<'a> {
    events: Vec<Event<'a>>,
    used_bytes: usize,
}
fn parse_log(data: &[u8]) -> Result<Log<'_>> {
    if !(32..=MAX_LOG_BYTES).contains(&data.len()) {
        return Err(VerificationError::ResourceLimit("gcp_ccel_size"));
    }
    let mut c = Cursor::new(data);
    if c.u32()? > 1 || c.u32()? != NO_ACTION || c.take(20)? != [0; 20] {
        return Err(invalid("gcp_ccel_initial_event"));
    }
    let spec_size = c.u32()? as usize;
    if !(33..=1024).contains(&spec_size) {
        return Err(invalid("gcp_ccel_spec_size"));
    }
    spec_id(c.take(spec_size)?)?;
    let mut events = Vec::new();
    while !c.remaining().is_empty() {
        let rest = c.remaining();
        if rest.len() >= 8 && (rest[..8] == [0; 8] || rest[..8] == [0xff; 8]) {
            if rest.iter().any(|b| *b != rest[0]) {
                return Err(invalid("gcp_ccel_hidden_padding"));
            }
            break;
        }
        if events.len() >= MAX_EVENTS {
            return Err(VerificationError::ResourceLimit("gcp_ccel_events"));
        }
        let mr = c.u32()?;
        let kind = c.u32()?;
        let count = c.u32()?;
        if mr > 4
            || count > 1
            || !matches!(
                kind,
                NO_ACTION
                    | SEPARATOR
                    | 0x0a
                    | 0x8000_0001
                    | 0x8000_0002
                    | EFI_APP
                    | EFI_GPT
                    | EFI_ACTION
                    | 0x8000_000a
                    | 0x8000_000b
            )
        {
            return Err(invalid("gcp_ccel_event_profile"));
        }
        let event_digest = if count == 1 {
            if c.u16()? != SHA384_ALG {
                return Err(invalid("gcp_ccel_digest_algorithm"));
            }
            Some(c.array::<48>()?)
        } else {
            None
        };
        if (kind != NO_ACTION && (event_digest.is_none() || mr == 0))
            || (kind == NO_ACTION && event_digest.is_some_and(|d| d != [0; 48]))
        {
            return Err(invalid("gcp_ccel_measured_event"));
        }
        let size = c.u32()? as usize;
        if size > MAX_EVENT_DATA_BYTES {
            return Err(VerificationError::ResourceLimit("gcp_ccel_event_size"));
        }
        let event_data = c.take(size)?;
        if kind == EFI_APP {
            image_load(event_data)?;
        }
        events.push(Event {
            mr,
            kind,
            digest: event_digest,
            data: event_data,
        });
    }
    Ok(Log {
        events,
        used_bytes: c.offset,
    })
}

fn check_gpt_event(event: &Event<'_>) -> Result<()> {
    // TCG_EFI_GPT_DATA: EFI_PARTITION_TABLE_HEADER followed by UINT64
    // NumberOfPartitions and that many 128-byte EFI_PARTITION_ENTRYs. Disk
    // identifiers and CRC fields are measured data, not independent authority.
    let mut c = Cursor::new(event.data);
    if c.take(8)? != b"EFI PART" || c.u32()? != 0x0001_0000 || c.u32()? != 92 {
        return Err(invalid("gcp_boot_gpt_header"));
    }
    c.u32()?; // Header CRC32 is not an independent disk-integrity claim.
    if c.u32()? != 0 {
        return Err(invalid("gcp_boot_gpt_reserved"));
    }
    c.take(56)?; // LBAs, disk GUID, partition-entry LBA.
    let capacity = c.u32()? as u64;
    if c.u32()? != 128 {
        return Err(invalid("gcp_boot_gpt_entry_size"));
    }
    c.u32()?; // Partition-entry-array CRC32.
    let count = c.u64()?;
    if count == 0 || count > capacity || count > 1024 {
        return Err(invalid("gcp_boot_gpt_count"));
    }
    c.take(count as usize * 128)?;
    c.end()?;
    if event.digest != Some(sha384(event.data)) {
        return Err(invalid("gcp_boot_gpt_digest"));
    }
    Ok(())
}

fn data_digest(event: &Event<'_>, data: &[u8]) -> bool {
    event.data == data && event.digest == Some(sha384(data))
}

/// Strict direct-PE event sequence, without interpreting labels as causality.
fn check_sequence(events: &[Event<'_>], expected_pe: &[u8; 48]) -> Result<()> {
    let mut stage = 0;
    let mut separator1 = false;
    let mut gpt = false;
    for event in events {
        match stage {
            0 => {
                if event.kind == EFI_ACTION
                    && event.mr == 2
                    && data_digest(event, CALL_APPLICATION)
                    && separator1
                {
                    stage = 1;
                } else if event.kind == NO_ACTION && event.mr == 0 {
                    // Informational firmware RIM records, never trust roots.
                } else if event.kind == SEPARATOR
                    && event.mr == 1
                    && !separator1
                    && data_digest(event, &[0; 4])
                {
                    separator1 = true;
                } else if event.mr == 1
                    && matches!(
                        event.kind,
                        0x0a | 0x8000_0001 | 0x8000_0002 | 0x8000_000a | 0x8000_000b
                    )
                {
                    // Firmware configuration prefix is replayed, not independently
                    // endorsed by labels. Its acceptance still requires policy.
                } else {
                    return Err(invalid("gcp_boot_prefix"));
                }
            }
            1 if event.mr == 2 && event.kind == SEPARATOR && data_digest(event, &[0; 4]) => {
                stage = 2
            }
            2 if event.mr == 2 && event.kind == EFI_GPT && !gpt => {
                check_gpt_event(event)?;
                gpt = true;
            }
            2 if gpt
                && event.mr == 2
                && event.kind == EFI_APP
                && event.digest.as_ref() == Some(expected_pe) =>
            {
                stage = 3
            }
            3 if event.mr == 2
                && event.kind == EFI_ACTION
                && data_digest(event, EXIT_INVOCATION) =>
            {
                stage = 4
            }
            4 if event.mr == 2 && event.kind == EFI_ACTION && data_digest(event, EXIT_SUCCESS) => {
                stage = 5
            }
            _ => return Err(invalid("gcp_boot_sequence")),
        }
    }
    if stage != 5 {
        return Err(invalid("gcp_boot_incomplete"));
    }
    Ok(())
}

pub fn check_boot_evidence(
    acpi_ccel: &[u8],
    ccel: &[u8],
    quote: &[u8],
    expected_full64: &[u8; 64],
    policy: &GcpBootEvidencePolicy,
) -> Result<StructuralBootEvidence> {
    let expected_pe = reference(&policy.expected_pe_sha384)?;
    let expected_firmware = reference(&policy.expected_firmware_mrtd)?;
    let expected_owner = policy.expected_instance.mr_owner()?;
    let quote = parse_quote(quote, policy.quote_padding)?;
    if quote.report_data != *expected_full64 {
        return Err(invalid("gcp_boot_report_data"));
    }
    if quote.mr_td != expected_firmware {
        return Err(invalid("gcp_boot_firmware"));
    }
    if quote.mr_owner != expected_owner {
        return Err(invalid("gcp_boot_instance"));
    }
    check_descriptor(acpi_ccel, ccel.len())?;
    let log = parse_log(ccel)?;
    let mut replayed = [[0u8; 48]; 4];
    let mut counts = [0; 4];
    for event in &log.events {
        if event.kind == NO_ACTION {
            continue;
        }
        // parse_log excludes index0 and missing digests for measured events.
        let index = (event.mr - 1) as usize;
        let mut extend = [0u8; 96];
        extend[..48].copy_from_slice(&replayed[index]);
        extend[48..].copy_from_slice(
            event
                .digest
                .as_ref()
                .ok_or_else(|| invalid("gcp_ccel_missing_digest"))?,
        );
        replayed[index] = sha384(&extend);
        counts[index] += 1;
    }
    if replayed != quote.rtmrs {
        return Err(invalid("gcp_ccel_rtmr_mismatch"));
    }
    check_sequence(&log.events, &expected_pe)?;
    Ok(StructuralBootEvidence {
        quote,
        event_count: log.events.len(),
        extended_event_counts: counts,
        used_log_bytes: log.used_bytes,
        log_sha384: sha384(ccel),
        descriptor_sha384: sha384(acpi_ccel),
    })
}

#[cfg(test)]
#[path = "gcp_boot_evidence_tests.rs"]
mod tests;
