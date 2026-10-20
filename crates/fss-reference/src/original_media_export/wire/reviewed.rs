#![forbid(unsafe_code)]
//! Version-two review pins. Their custody is checked online; offline verification binds exact bytes.

use fss_core::event::MAX_LINEAGE_DEPTH;

use super::*;
use crate::event_review::ReviewDisposition;

impl ReviewedMediaLineage {
    pub(super) fn encode(&self, e: &mut CanonicalEncoder) {
        e.digest(self.original_revision);
        e.digest(self.original_root);
        self.original_anchor.encode_canonical(e);
        e.u32(self.links.len() as u32);
        for link in &self.links {
            e.u64(link.revision);
            e.digest(link.event_revision);
            e.digest(link.event_root);
            link.event_anchor.encode_canonical(e);
            e.digest(link.statement_digest);
            e.digest(link.statement_root);
            e.text(link.disposition.as_str());
        }
    }

    pub(super) fn decode(d: &mut CanonicalDecoder<'_>) -> Result<Self> {
        let original_revision = d.digest()?;
        let original_root = d.digest()?;
        let original_anchor = LedgerAnchor::decode_canonical(d)?;
        let count = d.u32()? as usize;
        // A complete event lineage has at most 256 generations, one of which is native origin.
        // Even without variable anchor/text bytes, each link needs its generation and four hashes.
        if count == 0 || count >= MAX_LINEAGE_DEPTH || count > d.remaining() / 140 {
            return Err(OriginalMediaExportError::Limit);
        }
        let mut links = Vec::with_capacity(count);
        for _ in 0..count {
            links.push(VerifiedReviewLink {
                revision: d.u64()?,
                event_revision: d.digest()?,
                event_root: d.digest()?,
                event_anchor: LedgerAnchor::decode_canonical(d)?,
                statement_digest: d.digest()?,
                statement_root: d.digest()?,
                disposition: ReviewDisposition::parse(d.text()?)?,
            });
        }
        Ok(Self {
            original_revision,
            original_root,
            original_anchor,
            links,
        })
    }

    pub(super) fn validate(&self, record: &OriginalMediaExportRecord) -> Result<()> {
        if self.links.is_empty()
            || self.links.len() >= MAX_LINEAGE_DEPTH
            || !valid_digest(self.original_revision)
            || !valid_digest(self.original_root)
            || self.original_anchor.commit_sequence == 0
            || self.original_anchor.site_lineage != record.basis.site_lineage
            || self.original_anchor.ledger_epoch != record.basis.ledger_epoch
            || !valid_digest(self.original_anchor.state_root)
            || record.event_summary.event_revision() != self.links.len() as u64 + 1
        {
            return Err(OriginalMediaExportError::CustodyMismatch);
        }
        let mut previous_anchor = &self.original_anchor;
        let mut revisions = std::collections::BTreeSet::from([self.original_revision]);
        let mut roots = std::collections::BTreeSet::from([self.original_root]);
        let mut statements = std::collections::BTreeSet::new();
        let mut statement_roots = std::collections::BTreeSet::new();
        let mut previous_state = None;
        for (index, link) in self.links.iter().enumerate() {
            if link.revision != index as u64 + 2
                || ![
                    link.event_revision,
                    link.event_root,
                    link.statement_digest,
                    link.statement_root,
                    link.event_anchor.state_root,
                ]
                .into_iter()
                .all(valid_digest)
                || link.event_anchor.site_lineage != record.basis.site_lineage
                || link.event_anchor.ledger_epoch != record.basis.ledger_epoch
                || link.event_anchor.commit_sequence <= previous_anchor.commit_sequence
                || !revisions.insert(link.event_revision)
                || !roots.insert(link.event_root)
                || !statements.insert(link.statement_digest)
                || !statement_roots.insert(link.statement_root)
                || previous_state.is_some_and(|state| !link.disposition.allowed_from(state))
            {
                return Err(OriginalMediaExportError::CustodyMismatch);
            }
            previous_anchor = &link.event_anchor;
            previous_state = Some(link.disposition.state());
        }
        let last = self
            .links
            .last()
            .ok_or(OriginalMediaExportError::CustodyMismatch)?;
        if last.event_revision != record.request.event.expected_revision
            || last.event_root != record.event_summary.event_root()
            || &last.event_anchor != record.event_summary.event_anchor()
            || last.disposition.state() != record.event_summary.event_state()
            || record.basis.commit_sequence < last.event_anchor.commit_sequence
        {
            return Err(OriginalMediaExportError::CustodyMismatch);
        }
        Ok(())
    }

    pub(super) fn json_fields(&self) -> String {
        let links = self
            .links
            .iter()
            .map(|link| {
                format!(
                    concat!(
                        "{{\"revision\":{},\"event_revision\":{},\"event_root\":{},",
                        "\"authority_sequence\":{},\"authority_anchor_digest\":{},",
                        "\"statement_digest\":{},\"statement_root\":{},\"disposition\":{},",
                        "\"assertion_class\":\"operator\",\"sensor_support_added\":false}}"
                    ),
                    link.revision,
                    json(&link.event_revision.to_text()),
                    json(&link.event_root.to_text()),
                    link.event_anchor.commit_sequence,
                    anchor_json(&link.event_anchor),
                    json(&link.statement_digest.to_text()),
                    json(&link.statement_root.to_text()),
                    json(link.disposition.as_str()),
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        format!(
            concat!(
                ",\"reviewed_event\":true,\"native_origin_revision\":{},\"native_origin_event_root\":{},",
                "\"native_origin_authority_sequence\":{},\"native_origin_authority_anchor_digest\":{},",
                "\"review_count\":{},\"review_chain\":[{}],\"review_reasons_included\":false,",
                "\"reviewer_identity_included\":false,\"review_is_sensor_recomputation\":false"
            ),
            json(&self.original_revision.to_text()),
            json(&self.original_root.to_text()),
            self.original_anchor.commit_sequence,
            anchor_json(&self.original_anchor),
            self.links.len(),
            links,
        )
    }
}

fn anchor_json(anchor: &LedgerAnchor) -> String {
    json(
        &anchor
            .canonical_digest("fss.original_media_export_basis.v1")
            .to_text(),
    )
}
