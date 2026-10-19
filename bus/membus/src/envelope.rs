// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! Flat RESP field envelope.
//!
//! One envelope shape for both delivery classes. Flat field-value
//! pairs - RESP-native, no nested JSON, no `HashMap` allocation on
//! parse. Fields, in wire order:
//!
//! ```text
//! et  <event_type>     platform naming: {vertical}:{service}:{resource}:{operation}
//! ts  <unix_micros>
//! cid <correlation_id> propagated from the originating request when known
//! by  <producer>       stamped by the library from the configured service
//!                     name - informative, not authoritative
//! sq  <seq>           per-(service, family) monotonic sequence - dedupe key
//! p   <payload>        opaque bytes
//! ```
//!
//! **No `publisher_id_token`, no `env_id` inside the message.** Tenant
//! identity is a property of the *key* (`mbus:{env}:…`), never of the
//! payload - a subscriber trusts the key because its ACL and connection
//! context guarantee the namespace, not because the message says so.

/// Field names, in wire order.
pub const FIELD_EVENT_TYPE: &str = "et";
/// Producer timestamp field name (unix microseconds).
pub const FIELD_TIMESTAMP: &str = "ts";
/// Correlation id field name.
pub const FIELD_CORRELATION: &str = "cid";
/// Producer identity field name.
pub const FIELD_PRODUCER: &str = "by";
/// Sequence number field name.
pub const FIELD_SEQ: &str = "sq";
/// Opaque payload field name.
pub const FIELD_PAYLOAD: &str = "p";

/// An outbound envelope under construction / an inbound envelope
/// decoded from fields or a frame.
#[derive(Debug, Clone, PartialEq)]
pub struct Envelope {
    /// Event type - the platform colon convention, e.g.
    /// `hotel8:pms:reservation:created`.
    pub event_type: String,
    /// Producer timestamp, unix microseconds.
    pub ts_us: u64,
    /// Correlation id - propagated from the originating request when
    /// known; empty when none.
    pub correlation_id: String,
    /// Producer service name - stamped by the library.
    pub producer: String,
    /// Per-(service, family) sequence number - dedupe/gap key.
    pub sq: u64,
    /// Opaque payload bytes.
    pub payload: Vec<u8>,
}

/// One wire field - borrowed view over an encoded or decoded envelope.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EnvelopeField<'a> {
    /// The field name (one of the `FIELD_*` constants).
    pub name: &'a str,
    /// The raw field value bytes.
    pub value: &'a [u8],
}

/// Envelope wire-encoding helpers.
impl Envelope {
    /// Build an envelope. `ts` is stamped now; `sq` is assigned by the
    /// caller (EnvBus) so it stays per-(service, family) monotonic.
    pub fn new(event_type: impl Into<String>, payload: impl Into<Vec<u8>>) -> Self {
        Self {
            event_type: event_type.into(),
            ts_us: now_micros(),
            correlation_id: String::new(),
            producer: String::new(),
            sq: 0,
            payload: payload.into(),
        }
    }

    /// Stamp the producer identity (`by` - the library does this from
    /// config; kept public for tests and atypical embedding).
    pub fn with_producer(mut self, producer: impl Into<String>) -> Self {
        self.producer = producer.into();
        self
    }

    /// Attach a correlation id.
    pub fn with_correlation(mut self, cid: impl Into<String>) -> Self {
        self.correlation_id = cid.into();
        self
    }

    /// Assign the sequence number (done by `EnvBus` at publish time).
    pub fn with_sq(mut self, sq: u64) -> Self {
        self.sq = sq;
        self
    }

    /// Iterate wire fields in order - used for XADD and frame encoding.
    /// Numeric fields (`ts`, `sq`) are rendered to short-lived owned
    /// strings; the caller consumes them within one publish.
    pub fn iter_fields(&self) -> Vec<(&'static str, FieldValue<'_>)> {
        vec![
            (
                FIELD_EVENT_TYPE,
                FieldValue::Borrowed(self.event_type.as_bytes()),
            ),
            (FIELD_TIMESTAMP, FieldValue::Owned(self.ts_us.to_string())),
            (
                FIELD_CORRELATION,
                FieldValue::Borrowed(self.correlation_id.as_bytes()),
            ),
            (
                FIELD_PRODUCER,
                FieldValue::Borrowed(self.producer.as_bytes()),
            ),
            (FIELD_SEQ, FieldValue::Owned(self.sq.to_string())),
            (FIELD_PAYLOAD, FieldValue::Borrowed(&self.payload)),
        ]
    }

    /// Encode to a flat binary frame for the pub/sub class - the hot
    /// path skips serde entirely.
    ///
    /// Frame layout (little-endian u16/u32 length prefixes):
    /// `[nname][name][nval][value]…` repeated for every field.
    pub fn encode_frame(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + self.payload.len());
        for (name, value) in self.iter_fields() {
            let value: &[u8] = value.as_bytes();
            put_u16(&mut out, name.len() as u16);
            out.extend_from_slice(name.as_bytes());
            put_u32(&mut out, value.len() as u32);
            out.extend_from_slice(value);
        }
        out
    }

    /// Decode a binary frame into an owned envelope. Allocates only for
    /// the owned fields - no intermediate map.
    pub fn decode_frame(frame: &[u8]) -> Result<Self, String> {
        let mut env = Envelope {
            event_type: String::new(),
            ts_us: 0,
            correlation_id: String::new(),
            producer: String::new(),
            sq: 0,
            payload: Vec::new(),
        };
        let mut off = 0usize;
        while off < frame.len() {
            let name = take_str(frame, &mut off)?;
            let value = take_bytes(frame, &mut off)?;
            match name {
                FIELD_EVENT_TYPE => env.event_type = String::from_utf8_lossy(value).into_owned(),
                FIELD_TIMESTAMP => {
                    env.ts_us = std::str::from_utf8(value)
                        .ok()
                        .and_then(|v| v.parse().ok())
                        .ok_or_else(|| "bad ts".to_string())?
                }
                FIELD_CORRELATION => {
                    env.correlation_id = String::from_utf8_lossy(value).into_owned()
                }
                FIELD_PRODUCER => env.producer = String::from_utf8_lossy(value).into_owned(),
                FIELD_SEQ => {
                    env.sq = std::str::from_utf8(value)
                        .ok()
                        .and_then(|v| v.parse().ok())
                        .ok_or_else(|| "bad sq".to_string())?
                }
                FIELD_PAYLOAD => env.payload = value.to_vec(),
                _ => {} // unknown fields are skipped - forward compat
            }
        }
        Ok(env)
    }

    /// Field lookup by name over raw XADD field-value pairs - borrowed,
    /// no allocation.
    pub fn field<'a, V: AsRef<[u8]>>(fields: &'a [(String, V)], name: &str) -> Option<&'a [u8]> {
        fields
            .iter()
            .find(|(f, _)| f == name)
            .map(|(_, v)| v.as_ref())
    }

    /// Decode from raw XADD stream fields - byte values, because the
    /// `p` payload is opaque binary.
    pub fn from_stream_fields<V: AsRef<[u8]> + Clone>(
        fields: &[(String, V)],
    ) -> Result<Self, String> {
        let need = |name: &str| -> Result<Vec<u8>, String> {
            Self::field(fields, name)
                .map(|v| v.to_vec())
                .ok_or_else(|| format!("missing field {name}"))
        };
        let utf8 = |v: &[u8]| -> Result<String, String> {
            String::from_utf8(v.to_vec()).map_err(|_| "field not utf8".to_string())
        };
        let et = utf8(&need(FIELD_EVENT_TYPE)?)?;
        let ts = utf8(&need(FIELD_TIMESTAMP)?)
            .ok()
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| "bad ts".to_string())?;
        let sq = utf8(&need(FIELD_SEQ)?)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        Ok(Self {
            event_type: et,
            ts_us: ts,
            correlation_id: Self::field(fields, FIELD_CORRELATION)
                .and_then(|v| String::from_utf8(v.to_vec()).ok())
                .unwrap_or_default(),
            producer: Self::field(fields, FIELD_PRODUCER)
                .and_then(|v| String::from_utf8(v.to_vec()).ok())
                .unwrap_or_default(),
            sq,
            payload: Self::field(fields, FIELD_PAYLOAD)
                .map(|v| v.to_vec())
                .unwrap_or_default(),
        })
    }
}

/// Borrowed field view over decoded frame bytes - an iterator over
/// `(name, value)` slices with no per-message String allocation.
pub fn frame_fields(frame: &[u8]) -> Result<Vec<EnvelopeField<'_>>, String> {
    let mut out = Vec::with_capacity(6);
    let mut off = 0usize;
    while off < frame.len() {
        let name = take_str(frame, &mut off)?;
        let value = take_bytes(frame, &mut off)?;
        out.push(EnvelopeField { name, value });
    }
    Ok(out)
}

fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn take_u16(frame: &[u8], off: &mut usize) -> Result<u16, String> {
    if *off + 2 > frame.len() {
        return Err("frame truncated (u16)".into());
    }
    let v = u16::from_le_bytes([frame[*off], frame[*off + 1]]);
    *off += 2;
    Ok(v)
}

fn take_u32(frame: &[u8], off: &mut usize) -> Result<u32, String> {
    if *off + 4 > frame.len() {
        return Err("frame truncated (u32)".into());
    }
    let v = u32::from_le_bytes([
        frame[*off],
        frame[*off + 1],
        frame[*off + 2],
        frame[*off + 3],
    ]);
    *off += 4;
    Ok(v)
}

fn take_str<'a>(frame: &'a [u8], off: &mut usize) -> Result<&'a str, String> {
    let n = take_u16(frame, off)? as usize;
    if *off + n > frame.len() {
        return Err("frame truncated (name)".into());
    }
    let s = std::str::from_utf8(&frame[*off..*off + n])
        .map_err(|_| "field name not utf8".to_string())?;
    *off += n;
    Ok(s)
}

fn take_bytes<'a>(frame: &'a [u8], off: &mut usize) -> Result<&'a [u8], String> {
    let n = take_u32(frame, off)? as usize;
    if *off + n > frame.len() {
        return Err("frame truncated (value)".into());
    }
    let v = &frame[*off..*off + n];
    *off += n;
    Ok(v)
}

fn now_micros() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}

/// A wire-field value - borrowed bytes for string/payload fields, a
/// short-lived owned rendering for numeric fields.
#[derive(Debug, Clone)]
pub enum FieldValue<'a> {
    /// Bytes borrowed from the envelope's own storage (strings/payload).
    Borrowed(&'a [u8]),
    /// A short-lived owned rendering (numeric fields at encode time).
    Owned(String),
}

impl FieldValue<'_> {
    /// The raw field value bytes, borrowed or owned.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            FieldValue::Borrowed(b) => b,
            FieldValue::Owned(s) => s.as_bytes(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_round_trip_frame() {
        let env = Envelope::new("svc:me:trade:printed", b"{\"p\":1.08456}".to_vec())
            .with_producer("svc-me")
            .with_correlation("corr-42")
            .with_sq(7);
        let frame = env.encode_frame();
        let back = Envelope::decode_frame(&frame).unwrap();
        assert_eq!(back, env);
    }

    #[test]
    fn frame_fields_borrowed_no_alloc() {
        let env = Envelope::new("svc:rfq:quote:landed", vec![1, 2, 3])
            .with_producer("svc-rfq")
            .with_sq(99);
        let frame = env.encode_frame();
        let fields = frame_fields(&frame).unwrap();
        assert_eq!(fields.len(), 6);
        assert_eq!(fields[0].name, FIELD_EVENT_TYPE);
        assert_eq!(fields[4].name, FIELD_SEQ);
        assert_eq!(fields[4].value, b"99");
        assert_eq!(fields[5].value, &[1, 2, 3]);
    }

    #[test]
    fn stream_fields_decode() {
        let fields = vec![
            ("et".into(), "svc:me:trade:printed".into()),
            ("ts".into(), "1234567890".into()),
            ("cid".into(), "".into()),
            ("by".into(), "svc-me".into()),
            ("sq".into(), "5".into()),
            ("p".into(), "{\"qty\":100}".into()),
        ];
        let env = Envelope::from_stream_fields(&fields).unwrap();
        assert_eq!(env.event_type, "svc:me:trade:printed");
        assert_eq!(env.ts_us, 1_234_567_890);
        assert_eq!(env.sq, 5);
        assert_eq!(env.payload, b"{\"qty\":100}".to_vec());
        // Missing mandatory field errors.
        let bad: Vec<(String, String)> = fields.iter().skip(1).cloned().collect();
        assert!(Envelope::from_stream_fields(&bad).is_err());
    }

    #[test]
    fn iter_fields_wire_order() {
        let env = Envelope::new("a:b:c:d", vec![])
            .with_producer("svc")
            .with_sq(1);
        let names: Vec<&str> = env.iter_fields().iter().map(|(n, _)| *n).collect();
        assert_eq!(names, vec!["et", "ts", "cid", "by", "sq", "p"]);
    }

    #[test]
    fn numeric_field_rendering() {
        assert_eq!(0u64.to_string(), "0");
        assert_eq!(1_234_567_890u64.to_string(), "1234567890");
        assert_eq!(u64::MAX.to_string(), "18446744073709551615");
    }

    #[test]
    fn truncated_frame_never_panics_or_misreads() {
        let env = Envelope::new("a:b", vec![9, 9]).with_sq(5);
        let frame = env.encode_frame();
        // Every prefix either errors or decodes to a valid PARTIAL
        // envelope (lenient field boundaries - forward compat). The
        // invariants: never panic, never return a *wrong* sq - a
        // truncated numeric field must not decode to a bogus value.
        for cut in 0..=frame.len() {
            if let Ok(partial) = Envelope::decode_frame(&frame[..cut]) {
                // Partial decode keeps sq at 0 (unset) or the true 5.
                assert!(
                    partial.sq == 0 || partial.sq == 5,
                    "cut {cut}: bogus sq {}",
                    partial.sq
                );
            }
        }
        // Full frame round-trips with the exact sq.
        assert_eq!(Envelope::decode_frame(&frame).unwrap().sq, 5);
        // Malformed length prefixes (huge counts) must error.
        let mut bad = vec![0xFF, 0xFF];
        bad.extend_from_slice(&frame);
        assert!(Envelope::decode_frame(&bad).is_err());
    }
}
