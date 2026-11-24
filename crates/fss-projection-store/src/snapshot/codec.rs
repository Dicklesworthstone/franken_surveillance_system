#![forbid(unsafe_code)]
//! Verified binary `mvcc.snap` snapshot encoder/decoder and canonical table encoding helpers.

use std::collections::BTreeMap;
use std::sync::Arc;

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContractError, ObjectId,
    sha256,
};

use crate::error::ProjectionError;
use crate::schema::{
    DoctorScrubReceipt, FollowCommitSummary, HistoryChainMode, PROJECTION_SNAPSHOT_DOMAIN,
    ProjectedCoverageState, ProjectedEventSummary, ProjectedFootageImport, ProjectedHold,
    ProjectedIndeterminateEffect, ProjectedObligation, ProjectedPrivacyMask, ProjectedRevisionRef,
    ProjectedSensorLiveness, ProjectionAnchor,
};
use crate::schema_codec::MAX_DECODE_VEC_LEN;
use crate::snapshot::{PROJECTION_SNAPSHOT_MAGIC, PROJECTION_SNAPSHOT_VERSION, ProjectionSnapshot};
use crate::tables::{COMMIT_LOG_CHUNK_SIZE, ObjectEntityRef, ProjectionTables, object_id_shard};

const SNAPSHOT_TRAILER_LEN: usize = 32;

impl ProjectionSnapshot {
    /// Serializes this snapshot into verified `FMVS` v1 binary bytes bound to
    /// [`PROJECTION_SNAPSHOT_DOMAIN`] with a trailing whole-file SHA-256 checksum.
    pub fn encode_snapshot_bytes(&self) -> Result<Vec<u8>, ProjectionError> {
        let mut body_enc = CanonicalEncoder::new();
        self.anchor.encode_canonical(&mut body_enc);
        encode_tables_canonical(&self.tables, &mut body_enc);
        encode_object_entity_index(&self.tables, &mut body_enc);
        match &self.scrub_receipt {
            Some(receipt) => {
                body_enc.bool(true);
                receipt.encode_canonical(&mut body_enc);
            }
            None => body_enc.bool(false),
        }
        let body = body_enc.finish_checked()?;

        let domain = PROJECTION_SNAPSHOT_DOMAIN.as_bytes();
        let mut out = Vec::with_capacity(
            4 + 2 + 2 + 4 + domain.len() + 1 + body.len() + SNAPSHOT_TRAILER_LEN,
        );
        out.extend_from_slice(&PROJECTION_SNAPSHOT_MAGIC);
        out.extend_from_slice(&PROJECTION_SNAPSHOT_VERSION.to_be_bytes());
        out.extend_from_slice(&0_u16.to_be_bytes());
        out.extend_from_slice(&(domain.len() as u32).to_be_bytes());
        out.extend_from_slice(domain);
        out.push(self.history_mode.to_tag());
        out.extend_from_slice(&body);
        let trailer = sha256(&out);
        out.extend_from_slice(&trailer);
        Ok(out)
    }

    /// Decodes and cryptographically verifies an `FMVS` v1 `mvcc.snap` byte buffer.
    pub fn decode_snapshot_bytes(raw: &[u8]) -> Result<Self, ProjectionError> {
        let min_len = 4 + 2 + 2 + 4 + 1 + SNAPSHOT_TRAILER_LEN;
        if raw.len() < min_len {
            return Err(ProjectionError::CorruptDerivedStore {
                artifact: "mvcc.snap",
                detail: "snapshot shorter than minimum header + trailer".to_owned(),
            });
        }
        let body_end = raw.len() - SNAPSHOT_TRAILER_LEN;
        let (signed_part, trailer) = raw.split_at(body_end);
        if sha256(signed_part) != trailer {
            return Err(ProjectionError::CorruptDerivedStore {
                artifact: "mvcc.snap",
                detail: "SHA-256 trailer mismatch".to_owned(),
            });
        }
        if signed_part[0..4] != PROJECTION_SNAPSHOT_MAGIC {
            return Err(ProjectionError::CorruptDerivedStore {
                artifact: "mvcc.snap",
                detail: "invalid snapshot magic".to_owned(),
            });
        }
        let version = u16::from_be_bytes([signed_part[4], signed_part[5]]);
        if version != PROJECTION_SNAPSHOT_VERSION {
            return Err(ProjectionError::CorruptDerivedStore {
                artifact: "mvcc.snap",
                detail: format!("unsupported snapshot version {version}"),
            });
        }
        let flags = u16::from_be_bytes([signed_part[6], signed_part[7]]);
        if flags != 0 {
            return Err(ProjectionError::CorruptDerivedStore {
                artifact: "mvcc.snap",
                detail: format!("non-zero snapshot flags {flags}"),
            });
        }
        let domain_len = u32::from_be_bytes([
            signed_part[8],
            signed_part[9],
            signed_part[10],
            signed_part[11],
        ]) as usize;
        let domain_end = 12_usize
            .checked_add(domain_len)
            .ok_or(ProjectionError::ArithmeticOverflow("snapshot_domain_len"))?;
        if domain_end >= signed_part.len() {
            return Err(ProjectionError::CorruptDerivedStore {
                artifact: "mvcc.snap",
                detail: "snapshot domain length exceeds payload".to_owned(),
            });
        }
        if &signed_part[12..domain_end] != PROJECTION_SNAPSHOT_DOMAIN.as_bytes() {
            return Err(ProjectionError::CorruptDerivedStore {
                artifact: "mvcc.snap",
                detail: "snapshot domain tag mismatch".to_owned(),
            });
        }
        let history_mode =
            HistoryChainMode::from_tag(signed_part[domain_end]).ok_or_else(|| {
                ProjectionError::CorruptDerivedStore {
                    artifact: "mvcc.snap",
                    detail: "invalid history_mode tag".to_owned(),
                }
            })?;
        let mut decoder = CanonicalDecoder::new(&signed_part[domain_end + 1..]);
        let anchor = ProjectionAnchor::decode_canonical(&mut decoder).map_err(corrupt_snap)?;
        let mut tables = decode_tables_canonical(&mut decoder).map_err(corrupt_snap)?;
        decode_object_entity_index(&mut tables, &mut decoder).map_err(corrupt_snap)?;
        let scrub_receipt = if decoder.bool().map_err(corrupt_snap)? {
            Some(DoctorScrubReceipt::decode_canonical(&mut decoder).map_err(corrupt_snap)?)
        } else {
            None
        };
        decoder.ensure_finished().map_err(corrupt_snap)?;
        tables.rebuild_secondary_indexes_and_counters();

        Ok(Self {
            anchor,
            history_mode,
            tables,
            scrub_receipt,
        })
    }
}

fn corrupt_snap(err: ContractError) -> ProjectionError {
    ProjectionError::CorruptDerivedStore {
        artifact: "mvcc.snap",
        detail: err.to_string(),
    }
}

pub(crate) fn encode_tables_canonical(tables: &ProjectionTables, encoder: &mut CanonicalEncoder) {
    encoder.u64(tables.latest_events.len() as u64);
    for ev in tables.latest_events.values() {
        ev.encode_canonical(encoder);
    }

    let rev_count: usize = tables.event_revisions.values().map(|m| m.len()).sum();
    encoder.u64(rev_count as u64);
    for revs in tables.event_revisions.values() {
        for rev in revs.values() {
            rev.encode_canonical(encoder);
        }
    }

    let cov_count: usize = tables.coverage_index.values().map(|m| m.len()).sum();
    encoder.u64(cov_count as u64);
    for zones in tables.coverage_index.values() {
        for cov in zones.values() {
            cov.encode_canonical(encoder);
        }
    }

    encoder.u64(tables.counters.total_footage_imports as u64);
    for bucket in tables.footage_imports.values() {
        for imp in bucket.values() {
            imp.encode_canonical(encoder);
        }
    }

    encoder.u64(tables.active_holds.len() as u64);
    for hold in tables.active_holds.values() {
        hold.encode_canonical(encoder);
    }

    encoder.u64(tables.privacy_masks.len() as u64);
    for mask in tables.privacy_masks.values() {
        mask.encode_canonical(encoder);
    }

    encoder.u64(tables.obligations.len() as u64);
    for ob in tables.obligations.values() {
        ob.encode_canonical(encoder);
    }

    encoder.u64(tables.indeterminate_effects.len() as u64);
    for eff in tables.indeterminate_effects.values() {
        eff.encode_canonical(encoder);
    }

    encoder.u64(tables.sensor_liveness.len() as u64);
    for live in tables.sensor_liveness.values() {
        live.encode_canonical(encoder);
    }

    encoder.u64(tables.counters.active_zset_edges as u64);
    for ((relation, source), targets) in tables.graph_edges_zset.iter() {
        for (target, &weight) in targets.iter() {
            encoder.text(relation);
            encoder.text(source);
            encoder.text(target);
            encoder.u64(weight as u64);
        }
    }

    let log_count: usize = tables.commit_log_index.values().map(|c| c.len()).sum();
    encoder.u64(log_count as u64);
    for chunk in tables.commit_log_index.values() {
        for summary in chunk.values() {
            summary.encode_canonical(encoder);
        }
    }
}

fn decode_len(decoder: &mut CanonicalDecoder<'_>) -> Result<usize, ContractError> {
    let raw = decoder.u64()?;
    let len = usize::try_from(raw).map_err(|_| ContractError::InvalidDigest)?;
    if len > MAX_DECODE_VEC_LEN {
        return Err(ContractError::InvalidDigest);
    }
    Ok(len)
}

fn decode_tables_canonical(
    decoder: &mut CanonicalDecoder<'_>,
) -> Result<ProjectionTables, ContractError> {
    let mut tables = ProjectionTables::default();

    let ev_len = decode_len(decoder)?;
    let events = Arc::make_mut(&mut tables.latest_events);
    for _ in 0..ev_len {
        let ev = ProjectedEventSummary::decode_canonical(decoder)?;
        events.insert(ev.event_id.clone(), ev);
    }

    let rev_len = decode_len(decoder)?;
    let rev_outer = Arc::make_mut(&mut tables.event_revisions);
    for _ in 0..rev_len {
        let rev = ProjectedRevisionRef::decode_canonical(decoder)?;
        let inner = rev_outer
            .entry(rev.event_id.clone())
            .or_insert_with(|| Arc::new(BTreeMap::new()));
        Arc::make_mut(inner).insert(rev.revision, rev);
    }

    let cov_len = decode_len(decoder)?;
    let cov_outer = Arc::make_mut(&mut tables.coverage_index);
    for _ in 0..cov_len {
        let cov = ProjectedCoverageState::decode_canonical(decoder)?;
        let inner = cov_outer
            .entry(cov.sensor_id.clone())
            .or_insert_with(|| Arc::new(BTreeMap::new()));
        Arc::make_mut(inner).insert(cov.zone_id.clone(), cov);
    }

    let imp_len = decode_len(decoder)?;
    let imp_outer = Arc::make_mut(&mut tables.footage_imports);
    for _ in 0..imp_len {
        let imp = ProjectedFootageImport::decode_canonical(decoder)?;
        let shard = imp.import_id.bytes()[0];
        let inner = imp_outer
            .entry(shard)
            .or_insert_with(|| Arc::new(BTreeMap::new()));
        Arc::make_mut(inner).insert(imp.import_id, imp);
    }

    let hold_len = decode_len(decoder)?;
    let holds = Arc::make_mut(&mut tables.active_holds);
    for _ in 0..hold_len {
        let hold = ProjectedHold::decode_canonical(decoder)?;
        holds.insert(hold.hold_id.clone(), hold);
    }

    let mask_len = decode_len(decoder)?;
    let masks = Arc::make_mut(&mut tables.privacy_masks);
    for _ in 0..mask_len {
        let mask = ProjectedPrivacyMask::decode_canonical(decoder)?;
        masks.insert(mask.sensor_id.clone(), mask);
    }

    let ob_len = decode_len(decoder)?;
    let obligations = Arc::make_mut(&mut tables.obligations);
    for _ in 0..ob_len {
        let ob = ProjectedObligation::decode_canonical(decoder)?;
        obligations.insert(ob.obligation_id.clone(), ob);
    }

    let eff_len = decode_len(decoder)?;
    let effects = Arc::make_mut(&mut tables.indeterminate_effects);
    for _ in 0..eff_len {
        let eff = ProjectedIndeterminateEffect::decode_canonical(decoder)?;
        effects.insert(eff.operation_id.clone(), eff);
    }

    let live_len = decode_len(decoder)?;
    let liveness = Arc::make_mut(&mut tables.sensor_liveness);
    for _ in 0..live_len {
        let live = ProjectedSensorLiveness::decode_canonical(decoder)?;
        liveness.insert(live.sensor_id.clone(), live);
    }

    let edge_len = decode_len(decoder)?;
    let edges = Arc::make_mut(&mut tables.graph_edges_zset);
    for _ in 0..edge_len {
        let relation = decoder.text()?.to_owned();
        let source = decoder.text()?.to_owned();
        let target = decoder.text()?.to_owned();
        let weight = decoder.u64()? as i64;
        if weight != 0 {
            let inner = edges
                .entry((relation, source))
                .or_insert_with(|| Arc::new(BTreeMap::new()));
            Arc::make_mut(inner).insert(target, weight);
        }
    }

    let log_len = decode_len(decoder)?;
    let log = Arc::make_mut(&mut tables.commit_log_index);
    for _ in 0..log_len {
        let summary = FollowCommitSummary::decode_canonical(decoder)?;
        let chunk_id = summary.commit_sequence / COMMIT_LOG_CHUNK_SIZE;
        let inner = log
            .entry(chunk_id)
            .or_insert_with(|| Arc::new(BTreeMap::new()));
        Arc::make_mut(inner).insert(summary.commit_sequence, summary);
    }

    Ok(tables)
}

fn encode_object_entity_index(tables: &ProjectionTables, encoder: &mut CanonicalEncoder) {
    let total: usize = tables.object_entity_index.values().map(|b| b.len()).sum();
    encoder.u64(total as u64);
    for bucket in tables.object_entity_index.values() {
        for (obj_id, entity) in bucket.iter() {
            obj_id.encode_canonical(encoder);
            entity.encode_canonical(encoder);
        }
    }
}

fn decode_object_entity_index(
    tables: &mut ProjectionTables,
    decoder: &mut CanonicalDecoder<'_>,
) -> Result<(), ContractError> {
    let total = decode_len(decoder)?;
    let outer = Arc::make_mut(&mut tables.object_entity_index);
    for _ in 0..total {
        let obj_id = ObjectId::decode_canonical(decoder)?;
        let entity = ObjectEntityRef::decode_canonical(decoder)?;
        let shard = object_id_shard(&obj_id);
        let bucket = outer
            .entry(shard)
            .or_insert_with(|| Arc::new(BTreeMap::new()));
        Arc::make_mut(bucket).insert(obj_id, entity);
    }
    Ok(())
}
