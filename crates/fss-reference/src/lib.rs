#![forbid(unsafe_code)]
//! Deterministic virtual acquisition and replay reference for FSS.
//!
//! Source truth is generated before transport truth. Delivery loss, duplication, reordering, and
//! corruption are explicit derived observations and can never rewrite retained source bytes. The
//! end-to-end helper publishes source/delivery object graphs root-last and then commits one
//! canonical authority delta through `fss-publication`.

mod adapter_replay;
pub mod agent_session;
mod alert;
mod bundle;
mod calibration;
mod capture;
mod clock;
mod clock_sync;
mod context_binding;
pub mod decode;
mod delivery;
pub mod doctor;
mod durable_effect;
mod encoded_fixture;
mod error;
mod extrinsics;
mod hydration;
pub mod ingest;
mod meaningful_delta;
pub mod media_fixture;
mod model;
mod outcome;
mod packet_fault;
mod policy;
pub mod preprocess;
pub mod reference_deployment;
pub mod rtsp;
pub mod scalar_executor;
mod situation;
mod situation_guard;
mod situation_sections;
mod source;
pub mod time_tolerance;

#[cfg(test)]
mod adapter_replay_tests;
#[cfg(test)]
mod alert_tests;
#[cfg(test)]
mod bundle_tests;
#[cfg(test)]
mod context_binding_tests;
#[cfg(test)]
mod hydration_tests;
#[cfg(test)]
mod meaningful_delta_tests;
#[cfg(test)]
mod model_tests;
#[cfg(test)]
mod outcome_tests;
#[cfg(test)]
mod policy_tests;
#[cfg(test)]
mod reference_deployment_tests;
#[cfg(test)]
mod situation_guard_tests;
#[cfg(test)]
mod situation_sections_tests;
#[cfg(test)]
mod situation_tests;
#[cfg(test)]
mod tests;

pub use adapter_replay::{
    ADP_REPLAY_CURRENT_STATE, ADP_REPLAY_GENERATION, ADP_REPLAY_GOLDEN_AUDIT_HASH,
    ADP_REPLAY_GOLDEN_STATE_ROOT, ADP_REPLAY_MAX_PACKET_BYTES, ADP_REPLAY_MAX_PACKETS,
    ADP_REPLAY_MAX_TOTAL_BYTES, ADP_REPLAY_PROMOTION_GATE, ADP_REPLAY_PROTOCOL_PROFILE,
    ADP_REPLAY_ROW_ID, ADP_REPLAY_SURFACE, ADP_REPLAY_TIER, DEFAULT_MAX_ROLLBACK_SNAPSHOT_BYTES,
    DEFAULT_MAX_ROLLBACK_SNAPSHOT_OBJECTS, ERR_ADAPTER_REPLAY_DIVERGED, ERR_REPLAY_DIVERGED,
    MAX_SCOPED_DIR_ATTEMPTS, ReplayAdapter, ReplayAdapterConfig, ReplayAdapterError,
    ReplayAuditRecord, ReplayCx, ReplayDivergence, ReplayExecutionOutput, ReplayExecutionRequest,
    ReplayIoAuthority, ReplayLifecycleState, ReplayTerminalStatus, ScopedLedgerDir,
    compute_audit_hash,
};
pub use agent_session::{
    ReferenceSessionError, ReferenceSessionLimits, ReferenceSessionStore, ResolvedSessionHandle,
    SessionAlias, SessionBindingRequest, SessionRefresh,
};
pub use alert::{
    PrepareAlertParams, ProviderDispatch, ProviderFailureReceipt, ProviderObservationReceipt,
    REFERENCE_ALERT_TERMINAL_PREDICATE, ReferenceAlertPlan, ReferenceAlertProvider,
    ReferenceProviderBehavior, alert_cancel_proof, dispatch_reference_alert,
    observe_reference_alert, prepare_reference_alert, reconcile_failed_reference_alert,
    reconcile_reference_alert, verify_reference_alert,
};
pub use bundle::{ReplayBundle, ReplayBundleError, ReplayCursor};
pub use calibration::{
    CalibrationError, CalibrationLifecycle, CalibrationLifecycleState, CalibrationSample,
    CameraIntrinsics, DistortionModel, Fixed64, IntrinsicsCertificate,
    IntrinsicsCertificateBuilder, IntrinsicsCovariance, IntrinsicsResidual,
    MAX_CALIBRATION_SAMPLES, MAX_CERTIFICATE_ID_BYTES, MAX_IMAGE_DIMENSION_PX,
    MAX_REPROJECTION_TOLERANCE_UPX, MICRO_UNIT_SCALE, MIN_CALIBRATION_SAMPLES,
};
pub use capture::{
    ReferenceCapture, ReferenceCaptureReceipt, SourceFaultSchedule, run_reference_capture,
    run_reference_capture_with_clock, run_reference_capture_with_source,
};
pub use clock::{MAX_SKEW_PPM, VirtualClock};
pub use clock_sync::{
    ClockOffsetSkewEstimator, ClockSyncEstimate, EstimatorConfig, EstimatorState, SyncFitResidual,
    TimeSyncSample,
};
pub use context_binding::{
    BoundReferenceSituationPublication, ReferenceContextBindingError,
    ReferenceExpansionBindingSpec, seal_bound_reference_publication_handoff,
};
pub use decode::{
    DecodedImage, JPEG_DECODER_GENERATION, JPEG_DECODER_GENERATION_NUMERIC, JpegDecodeError,
    JpegDecodeLimits, JpegSubsampling, decode_baseline_jpeg,
};
pub use delivery::{
    DeliveryContinuity, DeliveryDirective, DeliveryMutation, DeliveryPacket, DeliveryPlan,
    MAX_DELIVERY_DIRECTIVES,
};
pub use doctor::{DoctorCheck, DoctorReport, DoctorValue, DoctorVerdict, inspect_deployment};
pub use durable_effect::{
    DurableEffectError, DurableEffectJournal, EFFECT_TRANSITION_RECORD_KIND,
    EFFECT_TRANSITION_V2_RECORD_KIND, EffectJournalInspection, EffectJournalStatus,
    IndeterminateOperationInfo, LedgeredObligation, ObligationCounts, ObligationLedgerState,
    PendingLedgerObligation,
};
pub use encoded_fixture::{
    ContainerFormat, EncodedCameraGenerator, EncodedCameraSpec, EncodedFixtureError,
    EncodedFixtureKind, EncodedFrameFixture, FrameType, MAX_FIXTURE_FRAMES,
    MAX_FIXTURE_PAYLOAD_BYTES, MAX_FRAME_HEIGHT, MAX_FRAME_WIDTH, MAX_KEYFRAME_CADENCE,
    MIN_KEYFRAME_CADENCE, VideoCodec,
};
pub use error::ReferenceError;
pub use extrinsics::{
    ExtrinsicsCertificate, ExtrinsicsCertificateBuilder, ExtrinsicsCorrespondence,
    ExtrinsicsCovariance, ExtrinsicsError, ExtrinsicsLifecycle, ExtrinsicsLifecycleState,
    ExtrinsicsResidual, ExtrinsicsSolveRequest, ExtrinsicsSolver, MAX_EXTRINSICS_CORRESPONDENCES,
    MAX_EXTRINSICS_REPROJECTION_TOLERANCE_UPX, MIN_EXTRINSICS_CORRESPONDENCES,
    ReferenceExtrinsicsSolver, RigidTransform3D, solve_extrinsics,
};
pub use hydration::{
    PublishedSourceReader, ReferenceHydrationCatalog, ReferenceHydrationLimits,
    SOURCE_OBJECT_CONTENT_TYPE, SourceHydrationError, SourceObjectBinding,
};
pub use ingest::{
    ADP_FILE_GENERATION, ADP_FILE_ROW_ID, AnnexBAccessUnit, AnnexBError, AnnexBLimits, AnnexBNal,
    AnnexBScan, CEILING_MAX_NAL_BYTES, CaptureHint, DEFAULT_CHUNK_BYTES, DEFAULT_MAX_AUS,
    DEFAULT_MAX_INPUT_BYTES, DEFAULT_MAX_NAL_BYTES, DEFAULT_MAX_NALS, DetectedFileFormat,
    FILE_IMPORT_MANIFEST_SCHEMA, FileFormatHint, FileImportManifest, FileIngestAdapter,
    FileIngestError, FileIngestLimits, FileIngestOutcome, FileIngestReceipt, FileIngestRequest,
    FileOmissionSpan, JpegFinding, JpegFrameSpan, JpegProcess, JpegScan, JpegSofInfo,
    JpegSplitError, MjpegLimits, OmissionReason, OmissionSpan, SegmentSpan, SourceSpan,
    compute_import_identity, default_adapter_identity, fetch_segment_bytes, sniff_format,
    split_annexb, split_jpeg_stream,
};
pub use meaningful_delta::{
    classify_reference_meaningful_delta, classify_reference_meaningful_delta_in_lineage,
};
pub use model::{
    ADR_0004_ID, ADR_0004_TITLE, CorroboratedModelFinding, CorroborationStatus,
    MAX_CORROBORATION_SOURCES, MAX_DETECTIONS_PER_OUTPUT, MAX_EMBEDDING_DIM, MAX_FAULT_REASON_LEN,
    MAX_INPUT_PAYLOAD_BYTES, MAX_MODEL_GENERATION_BYTES, MockAbstentionReason, MockDetection,
    MockEmbedding, MockExecutorOutcome, MockModelError, MockModelExecutor, MockModelFaultSchedule,
    MockModelOutcome, MockModelOutput, MockModelResult, MockModelScript, MockModelSpec,
    MockOutputDigestRequest, MockSemanticLabel, ModelGenerationDescriptor,
    compare_model_embeddings, compare_model_scores, compute_output_digest,
    encode_coord_to_basis_point, evaluate_corroboration, execute_mock_model, fuse_model_embeddings,
    fuse_model_scores, is_latest_generation,
};
pub use outcome::{
    ALERT_OUTCOME_FAMILY, ReferenceAlertOutcome, ReferenceAlertOutcomeReceipt,
    publish_reference_alert_outcome,
};
pub use packet_fault::{
    DeterministicFaultPrng, FaultInjectionJournal, FaultRule, FaultStreamItem,
    InjectedFaultEvidence, InjectedGapWitness, MAX_BUFFER_CAPACITY, MAX_DUPLICATE_COPIES,
    MAX_GAP_LENGTH, MAX_REORDER_WINDOW, MAX_SCHEDULE_RULES, PacketFaultError, PacketFaultInjector,
    PacketFaultSchedule, ScheduledGap, SequencedPacket, StochasticFaultProfile, inject_packets,
    inject_stream,
};
pub use policy::{
    ReferenceEventReceipt, ReferenceModelObservation, ReferencePolicyAction,
    ReferencePolicyDecision, evaluate_unknown_presence, publish_reference_event,
};
pub use reference_deployment::{
    DEPLOYMENT_CANCEL_STAGES, DEPLOYMENT_LAYOUT_FILENAME, DEPLOYMENT_LAYOUT_FORMAT_VERSION,
    DEPLOYMENT_LAYOUT_SCHEMA, DeploymentLayout, DeploymentLimits, HostLayoutIo, LayoutIo,
    RecoveryAction, RecoveryReceipt, ReferenceDeployment, StagedManifestHandle,
    write_layout_atomic,
};
pub use rtsp::{
    DEFAULT_MAX_BODY_BYTES, DEFAULT_MAX_HEADERS, DEFAULT_MAX_INTERLEAVED_BYTES,
    DEFAULT_MAX_LINE_BYTES, MAX_BASE64_INPUT_BYTES, MAX_SDP_LINE_BYTES, MAX_SDP_LINES,
    REDACTED_CREDENTIAL, RtspError, RtspEvent, RtspHeader, RtspHeaders, RtspLimits, RtspMethod,
    RtspParser, RtspRequest, RtspResponse, RtspTransport, SdpError, SdpMedia, SdpSession,
    decode_base64, parse_sdp, parse_sdp_bytes,
};
pub use scalar_executor::{
    ChannelTransform, ExecBudget, ExecError, ExecOutcome, PreprocessProgram, ScalarExecCx,
    ScalarExecutor, deterministic_exp_f32, deterministic_sigmoid_f32,
};
pub use situation_guard::{
    CAPABILITY_EFFECT_RECONCILE, EFFECT_RECONCILE_AFFORDANCE, EFFECT_STATUS_AFFORDANCE,
    EffectCellKind, ReferenceSituation, ReferenceSituationRequest, compile_reference_situation,
    compile_reference_situation_with_durable_journal,
    compile_reference_situation_with_operation_receipt, seal_reference_handoff,
};
pub use situation_sections::{
    RedundancyRecord, ReferenceProjectionSpec, ReferenceSituationPublication,
    compile_reference_situation_publication,
    compile_reference_situation_publication_with_operation_receipt, latest_reference_publication,
    project_reference_situation, record_reference_publication, seal_reference_publication_handoff,
};
pub use source::{
    MAX_VIRTUAL_PACKET_BYTES, MAX_VIRTUAL_PACKETS, SourcePacket, VirtualCameraSpec, VirtualSource,
    generate_source, generate_source_with_clock,
};
pub use time_tolerance::{
    AssociationDecision, ClockSyncState, ERR_CLOCK_UNCERTAIN_001, EnforcementOutcome,
    ExceedanceConsequence, FORMAL_010_THEOREM_TAG, OperationTimeTolerance, RequiredClockEvidence,
    SourceTimeEvidence, SourceTimeEvidenceBuilder, SourceTimeEvidenceParams,
    TimeSensitiveOperation, TimeToleranceError, TimeUncertaintyBudget, UncertaintySources,
    evaluate_cross_camera_association,
};

pub(crate) use delivery::DeliveryTrace;
pub(crate) use source::SourceTrace;
