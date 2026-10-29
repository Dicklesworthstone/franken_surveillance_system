#![forbid(unsafe_code)]
//! Canonical bounded supervision command framing. Replay re-executes the state machine.

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncoder, EventId, LedgerAnchor, PrincipalId,
    SessionId, TimestampNs,
};

use super::{
    Command, DurableSessionError, MAX_EVENT_ID_BYTES, MAX_SUBSCRIPTION_BYTES,
    MAX_SUPERVISION_CONFIGURATION_BYTES, MAX_SUPERVISION_RECORD_BYTES,
    MAX_SUPERVISION_REPORT_BYTES, MAX_SUPERVISION_SOURCES, Record, SupervisionDetectionSourcePin,
    SupervisionRegistration, SupervisionSourcePin, optional_digest, validate_source_inventories,
};

const RECORD_DOMAIN: &str = "fss.reference_supervision_command.v1";
type Result<T> = std::result::Result<T, DurableSessionError>;

fn text(d: &mut CanonicalDecoder<'_>, maximum: usize) -> Result<String> {
    let value = d.text()?;
    if value.len() > maximum {
        return Err(DurableSessionError::CapacityExceeded);
    }
    Ok(value.to_owned())
}
fn bytes(d: &mut CanonicalDecoder<'_>, maximum: usize) -> Result<Vec<u8>> {
    let value = d.bytes()?;
    if value.len() > maximum {
        return Err(DurableSessionError::CapacityExceeded);
    }
    Ok(value.to_vec())
}
fn count(d: &mut CanonicalDecoder<'_>, maximum: usize) -> Result<usize> {
    let value = usize::try_from(d.u64()?).map_err(|_| DurableSessionError::CapacityExceeded)?;
    if value > maximum {
        return Err(DurableSessionError::CapacityExceeded);
    }
    Ok(value)
}
fn anchor(d: &mut CanonicalDecoder<'_>) -> Result<LedgerAnchor> {
    let value = LedgerAnchor::decode_canonical(d)?;
    if value.site_lineage.len() > 512 {
        return Err(DurableSessionError::CapacityExceeded);
    }
    Ok(value)
}
fn identity(e: &mut CanonicalEncoder, subscription: &str, expected: fss_core::ContentDigest) {
    e.text(subscription);
    e.digest(expected);
}

pub(super) fn encode_record(record: &Record) -> Result<Vec<u8>> {
    let mut e = CanonicalEncoder::new();
    e.text(RECORD_DOMAIN);
    e.text(record.principal.as_str());
    e.text(record.session.as_str());
    e.i128(record.now.0);
    e.digest(record.session_digest);
    e.digest(record.before_state);
    e.digest(record.after_state);
    match &record.command {
        // Inspection and recovery cannot change state or appear in committed replay history.
        Command::Inspect(_) | Command::Lookup(_) => {
            return Err(DurableSessionError::InvalidHistory);
        }
        Command::Register(registration) => {
            e.tag(0);
            registration.encode(&mut e);
        }
        Command::Reserve {
            subscription,
            expected,
            anchor,
        } => {
            e.tag(1);
            identity(&mut e, subscription, *expected);
            fss_core::CanonicalEncode::encode_canonical(anchor, &mut e);
        }
        Command::Publish {
            subscription,
            expected,
            reservation,
            payload,
            sources,
            detection_sources,
            report_receipt,
        } => {
            let event_health = sources.iter().any(|source| source.health_digest.is_some());
            e.tag(if !detection_sources.is_empty() {
                8
            } else if event_health {
                9
            } else {
                2
            });
            identity(&mut e, subscription, *expected);
            e.digest(*reservation);
            e.bytes(payload);
            e.u64(sources.len() as u64);
            for source in sources {
                source.encode(&mut e);
                if event_health {
                    optional_digest(&mut e, source.health_digest);
                }
            }
            e.digest(*report_receipt);
            if !detection_sources.is_empty() {
                e.u64(detection_sources.len() as u64);
                for source in detection_sources {
                    source.encode(&mut e);
                }
            }
        }
        Command::Release {
            subscription,
            expected,
            reservation,
            receipt,
        } => {
            e.tag(3);
            identity(&mut e, subscription, *expected);
            e.digest(*reservation);
            e.digest(*receipt);
        }
        Command::Acknowledge {
            subscription,
            expected,
            reservation,
            receipt,
            anchor,
        } => {
            e.tag(4);
            identity(&mut e, subscription, *expected);
            optional_digest(&mut e, *reservation);
            e.digest(*receipt);
            fss_core::CanonicalEncode::encode_canonical(anchor, &mut e);
        }
        Command::Discard {
            subscription,
            expected,
            receipt,
            anchor,
        } => {
            e.tag(5);
            identity(&mut e, subscription, *expected);
            e.digest(*receipt);
            fss_core::CanonicalEncode::encode_canonical(anchor, &mut e);
        }
        Command::ConfigureSchedule {
            registration,
            total_windows,
        } => {
            e.tag(6);
            registration.encode(&mut e);
            e.u32(*total_windows);
        }
        Command::Advance {
            subscription,
            expected,
            target_count,
            after_receipt,
            anchor,
        } => {
            e.tag(7);
            identity(&mut e, subscription, *expected);
            e.u32(*target_count);
            e.digest(*after_receipt);
            fss_core::CanonicalEncode::encode_canonical(anchor, &mut e);
        }
    }
    let bytes = e.finish_checked()?;
    if bytes.len() > MAX_SUPERVISION_RECORD_BYTES {
        return Err(DurableSessionError::CapacityExceeded);
    }
    Ok(bytes)
}

pub(super) fn decode_record(encoded: &[u8]) -> Result<Record> {
    if encoded.len() > MAX_SUPERVISION_RECORD_BYTES {
        return Err(DurableSessionError::CapacityExceeded);
    }
    let mut d = CanonicalDecoder::new(encoded);
    if d.text()? != RECORD_DOMAIN {
        return Err(DurableSessionError::InvalidHistory);
    }
    let principal = PrincipalId::parse(&text(&mut d, 512)?)?;
    let session = SessionId::parse(&text(&mut d, 512)?)?;
    let now = TimestampNs(d.i128()?);
    let session_digest = d.digest()?;
    let before_state = d.digest()?;
    let after_state = d.digest()?;
    let command = match d.tag()? {
        0 => Command::Register(SupervisionRegistration {
            session_id: SessionId::parse(&text(&mut d, 512)?)?,
            subscription_id: text(&mut d, MAX_SUBSCRIPTION_BYTES)?,
            configuration: bytes(&mut d, MAX_SUPERVISION_CONFIGURATION_BYTES)?,
            configuration_digest: d.digest()?,
            max_read_bytes: d.u64()?,
            max_read_attempts: d.u64()?,
            maximum_attempts: d.u32()?,
            max_report_bytes: count(&mut d, MAX_SUPERVISION_REPORT_BYTES)?,
        }),
        1 => Command::Reserve {
            subscription: text(&mut d, MAX_SUBSCRIPTION_BYTES)?,
            expected: d.digest()?,
            anchor: anchor(&mut d)?,
        },
        tag @ (2 | 8 | 9) => {
            let subscription = text(&mut d, MAX_SUBSCRIPTION_BYTES)?;
            let expected = d.digest()?;
            let reservation = d.digest()?;
            let payload = bytes(&mut d, MAX_SUPERVISION_REPORT_BYTES)?;
            let source_count = count(&mut d, MAX_SUPERVISION_SOURCES)?;
            let mut sources = Vec::with_capacity(source_count);
            for _ in 0..source_count {
                sources.push(SupervisionSourcePin {
                    event_id: EventId::parse(&text(&mut d, MAX_EVENT_ID_BYTES)?)?,
                    event_root: d.digest()?,
                    source_verified: d.bool()?,
                    health_digest: if tag == 9 && d.bool()? {
                        Some(d.digest()?)
                    } else {
                        None
                    },
                });
            }
            let report_receipt = d.digest()?;
            let mut detection_sources = Vec::new();
            if tag == 8 {
                let detection_count = count(&mut d, MAX_SUPERVISION_SOURCES - source_count)?;
                detection_sources.reserve(detection_count);
                for _ in 0..detection_count {
                    detection_sources.push(SupervisionDetectionSourcePin {
                        report_digest: d.digest()?,
                        record_digest: d.digest()?,
                        detection_root: d.digest()?,
                        source_verified: d.bool()?,
                        health_digest: if d.bool()? { Some(d.digest()?) } else { None },
                    });
                }
            }
            validate_source_inventories(&sources, &detection_sources)
                .map_err(|_| DurableSessionError::InvalidHistory)?;
            Command::Publish {
                subscription,
                expected,
                reservation,
                payload,
                sources,
                detection_sources,
                report_receipt,
            }
        }
        3 => Command::Release {
            subscription: text(&mut d, MAX_SUBSCRIPTION_BYTES)?,
            expected: d.digest()?,
            reservation: d.digest()?,
            receipt: d.digest()?,
        },
        4 => Command::Acknowledge {
            subscription: text(&mut d, MAX_SUBSCRIPTION_BYTES)?,
            expected: d.digest()?,
            reservation: if d.bool()? { Some(d.digest()?) } else { None },
            receipt: d.digest()?,
            anchor: anchor(&mut d)?,
        },
        5 => Command::Discard {
            subscription: text(&mut d, MAX_SUBSCRIPTION_BYTES)?,
            expected: d.digest()?,
            receipt: d.digest()?,
            anchor: anchor(&mut d)?,
        },
        6 => Command::ConfigureSchedule {
            registration: SupervisionRegistration {
                session_id: SessionId::parse(&text(&mut d, 512)?)?,
                subscription_id: text(&mut d, MAX_SUBSCRIPTION_BYTES)?,
                configuration: bytes(&mut d, MAX_SUPERVISION_CONFIGURATION_BYTES)?,
                configuration_digest: d.digest()?,
                max_read_bytes: d.u64()?,
                max_read_attempts: d.u64()?,
                maximum_attempts: d.u32()?,
                max_report_bytes: count(&mut d, MAX_SUPERVISION_REPORT_BYTES)?,
            },
            total_windows: d.u32()?,
        },
        7 => Command::Advance {
            subscription: text(&mut d, MAX_SUBSCRIPTION_BYTES)?,
            expected: d.digest()?,
            target_count: d.u32()?,
            after_receipt: d.digest()?,
            anchor: anchor(&mut d)?,
        },
        _ => return Err(DurableSessionError::InvalidHistory),
    };
    d.ensure_finished()?;
    let record = Record {
        principal,
        session,
        now,
        session_digest,
        before_state,
        after_state,
        command,
    };
    if encode_record(&record)? != encoded {
        return Err(DurableSessionError::InvalidHistory);
    }
    Ok(record)
}
