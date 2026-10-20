#![forbid(unsafe_code)]
//! Shared bounded fault transport for the two multipart ownership families.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use fss_core::{
    BudgetVector, ContentDigest, OperationId, RegionId, RegionKind, RegionTree, RootAuthoritySpec,
    RuntimeGrant, TimestampNs,
};
use fss_object::multipart::{
    ETag, MultipartTransport, PartReceipt, ProviderUploadState, Reconciliation, TransportCx,
    TransportOperation, UploadId, UploadIntent,
};
use fss_object::planner::PlannedChunk;
use fss_runtime::authority::AuthorityCx;

pub const RESOURCE: &str = "archive:test-store/evidence-object";
pub type Test = Result<(), Box<dyn std::error::Error>>;

pub fn budget() -> BudgetVector {
    let mut result = BudgetVector::ZERO;
    result.bytes = 64 * 1024 * 1024;
    result.network_bytes = result.bytes;
    result.storage_operations = 256;
    result
}

pub fn spec(
    operation: &str,
    allowance: BudgetVector,
) -> Result<RootAuthoritySpec, Box<dyn std::error::Error>> {
    Ok(RootAuthoritySpec {
        trace_id: "trace:multipart-family".into(),
        operation_id: OperationId::parse(operation)?,
        principal: "principal:test".into(),
        capabilities: [
            RuntimeGrant::ObjectStage,
            RuntimeGrant::ObjectPublish,
            RuntimeGrant::AdapterNet,
        ]
        .iter()
        .map(|grant| grant.as_str().to_owned())
        .collect(),
        deadline: None,
        priority: 10,
        budgets: allowance,
        privacy_scope: "privacy:test".into(),
        retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(b"multipart-family"),
        generation: 1,
    })
}

pub fn property() -> Result<(AuthorityCx, AuthorityCx, RegionTree), Box<dyn std::error::Error>> {
    let (mut root, mut tree) = AuthorityCx::root(
        spec("operation:root", budget())?,
        RegionId::new("region:process")?,
        RegionKind::Process,
        budget(),
        TimestampNs(0),
    )?;
    let property = root.scope_down(
        &mut tree,
        RegionId::new("region:property")?,
        RegionKind::Property,
        budget(),
        spec("operation:property", budget())?,
        TimestampNs(0),
    )?;
    Ok((root, property, tree))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorePhase {
    NotStarted,
    Active,
    Completed,
    Aborted,
}

#[derive(Debug)]
pub struct Store {
    pub phase: StorePhase,
    pub intent: Option<UploadIntent>,
    pub parts: BTreeMap<u64, PartReceipt>,
    pub calls: Vec<TransportOperation>,
    pub regions: Vec<RegionId>,
    pub fault_once: Option<TransportOperation>,
    pub fail_before_effect: bool,
    pub wrong_checksum_once: bool,
    pub unknown: bool,
    pub observation: Option<Reconciliation>,
    pub envelope_bytes: u64,
}
impl Default for Store {
    fn default() -> Self {
        Self {
            phase: StorePhase::NotStarted,
            intent: None,
            parts: BTreeMap::new(),
            calls: Vec::new(),
            regions: Vec::new(),
            fault_once: None,
            fail_before_effect: false,
            wrong_checksum_once: false,
            unknown: false,
            observation: None,
            envelope_bytes: 0,
        }
    }
}

#[derive(Default)]
pub struct MemoryTransport {
    pub store: Rc<RefCell<Store>>,
}

impl MemoryTransport {
    fn call(
        &self,
        cx: &mut TransportCx<'_>,
        operation: TransportOperation,
    ) -> Result<(bool, bool), String> {
        cx.checkpoint(cx.now()).map_err(|error| error.to_string())?;
        let envelope_bytes = self.store.borrow().envelope_bytes;
        cx.charge_io(cx.now(), envelope_bytes, envelope_bytes)
            .map_err(|error| error.to_string())?;
        assert_eq!(cx.operation(), operation);
        assert_eq!(cx.resource(), RESOURCE);
        assert_eq!(cx.authority().kind(), RegionKind::ObjectStore);
        let mut store = self.store.borrow_mut();
        store.calls.push(operation);
        store.regions.push(cx.authority().region().clone());
        let fail = store.fault_once == Some(operation);
        if fail {
            store.fault_once = None;
        }
        Ok((fail, store.fail_before_effect))
    }
    fn id() -> UploadId {
        UploadId("provider-upload-0".into())
    }
    fn bound(&self, intent: &UploadIntent) -> Result<(), String> {
        if self.store.borrow().intent.as_ref() != Some(intent) {
            return Err("intent mismatch".into());
        }
        Ok(())
    }
}

impl MultipartTransport for MemoryTransport {
    fn initiate(
        &mut self,
        cx: &mut TransportCx<'_>,
        intent: &UploadIntent,
    ) -> Result<UploadId, String> {
        let (fail, before) = self.call(cx, TransportOperation::Initiate)?;
        if fail && before {
            return Err("lost initiation outcome".into());
        }
        {
            let mut store = self.store.borrow_mut();
            if let Some(old) = &store.intent {
                if old != intent {
                    return Err("intent conflict".into());
                }
            } else {
                store.intent = Some(intent.clone());
            }
            store.phase = StorePhase::Active;
        }
        if fail {
            Err("initiation ACK lost".into())
        } else {
            Ok(Self::id())
        }
    }
    fn upload_part(
        &mut self,
        cx: &mut TransportCx<'_>,
        upload: &UploadId,
        chunk: &PlannedChunk,
        bytes: &[u8],
        digest: ContentDigest,
    ) -> Result<PartReceipt, String> {
        let (fail, before) = self.call(cx, TransportOperation::UploadPart)?;
        if fail && before {
            return Err("part outcome unknown".into());
        }
        assert_eq!(upload, &Self::id());
        assert_eq!(ContentDigest::sha256(bytes), digest);
        assert_eq!(bytes.len() as u64, chunk.len);
        let mut receipt = PartReceipt {
            index: chunk.index,
            content_digest: digest,
            etag: ETag(format!("\"opaque-provider-token-{}\"", chunk.index)),
        };
        let mut store = self.store.borrow_mut();
        if store.phase != StorePhase::Active {
            return Err("not active".into());
        }
        store.parts.insert(chunk.index, receipt.clone());
        if store.wrong_checksum_once {
            store.wrong_checksum_once = false;
            receipt.content_digest = ContentDigest::sha256(b"wrong-checksum");
        }
        if fail {
            Err("part ACK lost".into())
        } else {
            Ok(receipt)
        }
    }
    fn complete(
        &mut self,
        cx: &mut TransportCx<'_>,
        upload: &UploadId,
        intent: &UploadIntent,
        parts: &[PartReceipt],
    ) -> Result<(), String> {
        let (fail, before) = self.call(cx, TransportOperation::Complete)?;
        if fail && before {
            return Err("completion outcome unknown".into());
        }
        self.bound(intent)?;
        assert_eq!(upload, &Self::id());
        let mut store = self.store.borrow_mut();
        if parts != store.parts.values().cloned().collect::<Vec<_>>() {
            return Err("part mismatch".into());
        }
        store.phase = StorePhase::Completed;
        if fail {
            Err("completion ACK lost".into())
        } else {
            Ok(())
        }
    }
    fn abort(
        &mut self,
        cx: &mut TransportCx<'_>,
        upload: &UploadId,
        intent: &UploadIntent,
    ) -> Result<(), String> {
        let (fail, before) = self.call(cx, TransportOperation::Abort)?;
        if fail && before {
            return Err("abort outcome unknown".into());
        }
        self.bound(intent)?;
        assert_eq!(upload, &Self::id());
        let mut store = self.store.borrow_mut();
        if store.phase == StorePhase::Completed {
            return Err("already completed".into());
        }
        store.phase = StorePhase::Aborted;
        if fail {
            Err("abort ACK lost".into())
        } else {
            Ok(())
        }
    }
    fn reconcile(
        &mut self,
        cx: &mut TransportCx<'_>,
        intent: &UploadIntent,
    ) -> Result<Reconciliation, String> {
        let (fail, _) = self.call(cx, TransportOperation::Reconcile)?;
        if fail {
            return Err("query failed".into());
        }
        let store = self.store.borrow();
        if let Some(observation) = &store.observation {
            return Ok(observation.clone());
        }
        let state = if store.unknown {
            ProviderUploadState::Unknown
        } else {
            match store.phase {
                StorePhase::NotStarted => ProviderUploadState::NotStarted,
                StorePhase::Active => ProviderUploadState::Active {
                    upload: Self::id(),
                    parts: store.parts.values().cloned().collect(),
                },
                StorePhase::Completed => ProviderUploadState::Completed {
                    upload: Self::id(),
                    manifest_root: intent.manifest_root(),
                    parts: store.parts.values().cloned().collect(),
                },
                StorePhase::Aborted => ProviderUploadState::Aborted { upload: Self::id() },
            }
        };
        Ok(Reconciliation {
            intent_digest: intent.digest(),
            state,
        })
    }
}
