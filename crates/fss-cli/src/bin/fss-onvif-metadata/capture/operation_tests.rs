#![forbid(unsafe_code)]
//! Real native custody-hook regressions. These tests perform local deployment I/O;
//! they do not dispatch HTTP or claim camera interoperability.

use std::cell::Cell;
use std::path::PathBuf;

use fss_core::EffectState;
use fss_reference::onvif::control::{RetainedCreateIntent, RetainedSubscription, list_control};

use super::*;

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:native-capture-operation";
const OWNER: &str = "operator:native-capture-operation";
const MESSAGE: &str = "urn:fss:onvif:native-operation-first";
const SOURCE: &[u8] = br#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:e="http://www.onvif.org/ver10/events/wsdl" xmlns:w="http://www.w3.org/2005/08/addressing" xmlns:n="http://docs.oasis-open.org/wsn/b-2"><s:Header><w:RelatesTo>urn:fss:onvif:native-operation-first</w:RelatesTo></s:Header><s:Body><e:CreatePullPointSubscriptionResponse><e:SubscriptionReference><w:Address>http://192.0.2.4/onvif/private-native-operation-source?Idx=7</w:Address></e:SubscriptionReference><n:CurrentTime>2026-10-27T00:00:00Z</n:CurrentTime><n:TerminationTime>2026-10-27T00:02:00Z</n:TerminationTime></e:CreatePullPointSubscriptionResponse></s:Body></s:Envelope>"#;

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        let base = std::env::var_os("CARGO_TARGET_TMPDIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        for attempt in 0..64 {
            let path = base.join(format!(
                "fss-native-operation-{label}-{}-{attempt}",
                std::process::id(),
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("native operation fixture directories exhausted".into())
    }

    fn plan(&self, receive_origin: &str) -> Test<Plan> {
        let mut args = vec![OsString::from("--root"), self.0.as_os_str().to_owned()];
        for (key, value) in [
            ("--site", SITE),
            ("--principal", OWNER),
            ("--sensor", "sensor:native-operation"),
            ("--profile", "private-native-profile"),
            ("--peer", "192.0.2.4:80"),
            ("--authority", "192.0.2.4"),
            ("--events-path", "/onvif/events"),
            ("--service-root", "/onvif"),
            ("--owner-authorized", "yes"),
            ("--plaintext", "yes"),
            ("--subscribe", "yes"),
            ("--receive-origin-ns", receive_origin),
            ("--operation-id", "operation:native-retry-fence"),
        ] {
            args.extend([OsString::from(key), OsString::from(value)]);
        }
        for (key, value) in [
            (
                "--device-generation",
                ContentDigest::sha256(b"native-device-v1"),
            ),
            (
                "--profile-generation",
                ContentDigest::sha256(b"native-profile-v1"),
            ),
        ] {
            args.extend([OsString::from(key), OsString::from(value.to_text())]);
        }
        Ok(Plan::parse(&args)?)
    }

    fn context(&self, plan: &Plan) -> Test<ReplayCx> {
        // Use the native owner's actual explicitly scoped construction, including
        // the plan's principal and site. No default authority or fake deployment.
        let authority = storage_authority(plan, 64 * 1024 * 1024, 64)?;
        Ok(ReplayCx::from_context_authority_read_only(
            &authority,
            self.0.clone(),
        )?)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn create_intent<'a>(plan: &'a Plan, message_id: &'a str, started_ns: u64) -> PullPointControl<'a> {
    PullPointControl::CreateIntent {
        events: &plan.config.events,
        service_root: &plan.config.service_root,
        message_id,
        started_ns,
        lifetime_seconds: plan.config.lifetime_seconds,
    }
}

#[test]
fn restarted_native_hook_refuses_fresh_nonce_and_origin_without_losing_custody() -> Test {
    for response_retained in [false, true] {
        let directory = Directory::new(if response_retained {
            "response"
        } else {
            "lost-ack"
        })?;
        let plan = directory.plan("10000")?;
        let cx = directory.context(&plan)?;
        let deployment = RefCell::new(ReferenceDeployment::open(&plan.root, SITE, &cx)?);
        let mut receipts = ControlReceipts::default();
        let prepared = retain_control(
            &deployment,
            &plan,
            &mut receipts,
            create_intent(&plan, MESSAGE, 1000),
            &cx,
            || Ok(1050),
        )?;
        assert!(
            prepared.stop.is_none(),
            "first owned callback must permit its one dispatch"
        );
        let operation = receipts
            .operation
            .as_ref()
            .ok_or("operation receipt missing")?;
        assert_eq!(operation.receipt.state, EffectState::Committed);
        assert_eq!(operation.receipt.prepared_at, TimestampNs(11000));
        assert_eq!(operation.receipt.committed_at, Some(TimestampNs(11050)));
        let original_intent = receipts.intent.as_ref().ok_or("intent missing")?;
        let intent_handle = (
            original_intent.identity(),
            original_intent.publication_root(),
        );
        let created_handle = if response_retained {
            let observed = retain_control(
                &deployment,
                &plan,
                &mut receipts,
                PullPointControl::Created {
                    source: SOURCE,
                    message_id: MESSAGE,
                    started_ns: 1000,
                    completed_ns: 1100,
                    authenticated: false,
                },
                &cx,
                || Err(ClientError::Authority),
            )?;
            assert!(observed.stop.is_none());
            let created = receipts
                .created
                .as_ref()
                .ok_or("Create response receipt missing")?;
            Some((created.identity(), created.publication_root()))
        } else {
            None
        };
        drop(deployment);
        drop(receipts);

        let next = directory.plan("99000000")?;
        assert_eq!(plan.operation, next.operation);
        assert_ne!(plan.approval, next.approval);
        let cold_cx = directory.context(&next)?;
        let cold = RefCell::new(ReferenceDeployment::reopen(&next.root, SITE, &cold_cx)?);
        let prior_effect_root = cold.borrow().effects().last_root();
        let prior_batches = cold.borrow().ledger().batches().len();
        let mut repeated = ControlReceipts::default();
        let commit_clock_read = Cell::new(false);
        let refused = retain_control(
            &cold,
            &next,
            &mut repeated,
            create_intent(&next, "urn:fss:onvif:native-operation-fresh-nonce", 3000),
            &cold_cx,
            || {
                commit_clock_read.set(true);
                Ok(3100)
            },
        );
        assert!(matches!(refused, Err(MetadataError::Authority)));
        assert!(
            !commit_clock_read.get(),
            "existing operation refuses before another commit"
        );
        assert!(
            repeated.intent.is_none(),
            "retry must not publish a fresh wire intent"
        );
        assert_eq!(
            repeated.operation_error,
            Some("ERR-ONVIF-CAPTURE-OPERATION-EXISTING-001")
        );
        assert_eq!(
            repeated
                .operation
                .as_ref()
                .ok_or("existing operation receipt missing")?
                .receipt
                .state,
            EffectState::Indeterminate,
        );
        assert_eq!(cold.borrow().effects().last_root(), prior_effect_root);
        assert_eq!(cold.borrow().ledger().batches().len(), prior_batches);
        let retained = RetainedCreateIntent::open(
            &cold.borrow(),
            intent_handle.0,
            Some(intent_handle.1),
            &cold_cx,
        )?;
        assert_eq!(retained.binding().message_id, MESSAGE);
        assert_eq!(
            retained.binding().source.receive_interval.earliest,
            TimestampNs(11000)
        );
        if let Some((identity, root)) = created_handle {
            let created =
                RetainedSubscription::open(&cold.borrow(), identity, Some(root), &cold_cx)?;
            assert_eq!(created.source(), SOURCE);
            assert_eq!(created.intent_identity(), intent_handle.0);
        }
        assert_eq!(
            list_control(&cold.borrow(), 8, &cold_cx)?.len(),
            if response_retained { 2 } else { 1 }
        );
        assert!(
            !repeated
                .report()
                .contains("private-native-operation-source")
        );
    }
    Ok(())
}

#[test]
fn nonadvancing_commit_clock_keeps_prepared_id_and_intent_without_dispatch_permission() -> Test {
    for observed_now in [999, 1000] {
        let directory = Directory::new(&format!("clock-{observed_now}"))?;
        let plan = directory.plan("10000")?;
        let cx = directory.context(&plan)?;
        let deployment = RefCell::new(ReferenceDeployment::open(&plan.root, SITE, &cx)?);
        let mut receipts = ControlReceipts::default();
        assert!(
            retain_control(
                &deployment,
                &plan,
                &mut receipts,
                create_intent(&plan, MESSAGE, 1000),
                &cx,
                || Ok(observed_now),
            )
            .is_err()
        );
        let intent = receipts
            .intent
            .as_ref()
            .ok_or("known intent must survive clock refusal")?;
        let intent_handle = (intent.identity(), intent.publication_root());
        let binding = plan.operation.as_ref().ok_or("operation binding missing")?;
        let state = capture_operation::inspect(
            &deployment.borrow(),
            &binding.operation_id,
            Some(binding),
            None,
            &cx,
        )?;
        assert_eq!(state.receipt.state, EffectState::Prepared);
        assert_eq!(state.receipt.committed_at, None);
        drop(deployment);

        let next = directory.plan("20000")?;
        let cold_cx = directory.context(&next)?;
        let cold = RefCell::new(ReferenceDeployment::reopen(&next.root, SITE, &cold_cx)?);
        let mut retried = ControlReceipts::default();
        assert!(matches!(
            retain_control(
                &cold,
                &next,
                &mut retried,
                create_intent(&next, "urn:fss:onvif:after-clock-refusal", 4000),
                &cold_cx,
                || Ok(4100),
            ),
            Err(MetadataError::Authority),
        ));
        assert!(retried.intent.is_none());
        assert_eq!(
            retried.operation_error,
            Some("ERR-ONVIF-CAPTURE-OPERATION-EXISTING-001")
        );
        assert_eq!(
            retried
                .operation
                .as_ref()
                .ok_or("existing receipt missing")?
                .receipt
                .state,
            EffectState::Prepared
        );
        RetainedCreateIntent::open(
            &cold.borrow(),
            intent_handle.0,
            Some(intent_handle.1),
            &cold_cx,
        )?;
        assert_eq!(list_control(&cold.borrow(), 8, &cold_cx)?.len(), 1);
    }
    Ok(())
}
