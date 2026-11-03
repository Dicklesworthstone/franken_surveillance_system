#![forbid(unsafe_code)]
//! One source-custody owner for exact ended HTTP histories, independent of perception policy.

use fss_codec_mjpeg::DecodeBudget;
use fss_core::ContentDigest;
use fss_geometry::WorkBudget;
use fss_publication::{LocalRootPublisher, PublishCancellation, PublishCutPoint};

use super::file_adapter::FileIngestAdapter;
use super::http_history_watch::{HttpHistoryWatchBinding, HttpHistoryWatchError as Error};
use super::http_import::{
    HttpImportAuthority, HttpImportError, HttpImportReceipt, HttpImportRequest, MAX_BYTES,
    MAX_FRAMES, import_http,
};
use crate::http_reconnect_history::{
    ArchivedReconnectBoundary, ReconnectHistoryLimits, ReconnectHistoryPin,
    VerifiedReconnectHistory,
};
use crate::{ReferenceDeployment, ReplayCx};

type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy)]
pub(super) struct SourcePlan<'a> {
    pub pin: ReconnectHistoryPin,
    pub bindings: &'a [HttpHistoryWatchBinding],
}
#[derive(Clone, Copy)]
pub(super) struct SourceLimits {
    pub history: ReconnectHistoryLimits,
    pub maximum_frames_per_generation: usize,
    pub maximum_bytes_per_generation: u64,
}

impl SourcePlan<'_> {
    pub fn validate(self, limits: SourceLimits) -> Result<()> {
        self.pin
            .validate()
            .map_err(|_| Error::Invalid("history pin"))?;
        limits
            .history
            .validate()
            .map_err(|_| Error::Invalid("history limits"))?;
        if self.bindings.len() != self.pin.connections as usize
            || !(1..=MAX_FRAMES).contains(&limits.maximum_frames_per_generation)
            || !(1..=MAX_BYTES).contains(&limits.maximum_bytes_per_generation)
        {
            return Err(Error::Invalid("binding count or independent limits"));
        }
        let mut previous = 0;
        for binding in self.bindings {
            let hint = binding.capture_hint;
            if binding.generation <= previous
                || binding.receive_time.0 < 0
                || hint.start_ns.0 < 0
                || hint.assumed_fps <= 0.0
                || !hint.assumed_fps.is_finite()
            {
                return Err(Error::Invalid("ordered generation or capture timing"));
            }
            for index in [0, limits.maximum_frames_per_generation - 1] {
                FileIngestAdapter::compute_capture_interval(
                    index,
                    Some(&hint),
                    binding.receive_time,
                )
                .map_err(HttpImportError::from)?;
            }
            previous = binding.generation;
        }
        Ok(())
    }
}

pub(super) trait Authority {
    fn check(&self, destination: &ReferenceDeployment, cx: &ReplayCx) -> Result<()>;
}

#[derive(Debug)]
pub(super) struct ImportedGeneration {
    pub boundary: ArchivedReconnectBoundary,
    pub binding: HttpHistoryWatchBinding,
    pub import: Option<HttpImportReceipt>,
}

struct Access<'a> {
    authority: &'a dyn Authority,
    destination: &'a ReferenceDeployment,
    cx: &'a ReplayCx,
}
impl PublishCancellation for Access<'_> {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        self.authority.check(self.destination, self.cx).is_err()
    }
}
struct ImportAccess<'a> {
    authority: &'a dyn Authority,
    request: ContentDigest,
    cx: &'a ReplayCx,
}
impl HttpImportAuthority for ImportAccess<'_> {
    fn permit(&self, request: &HttpImportRequest, destination: &ReferenceDeployment) -> bool {
        request.digest().is_ok_and(|digest| digest == self.request)
            && self.authority.check(destination, self.cx).is_ok()
    }
}

pub(super) struct Sources<'a> {
    archive: &'a LocalRootPublisher,
    plan: SourcePlan<'a>,
    limits: SourceLimits,
    authority: &'a dyn Authority,
    import_stage: &'static str,
    history: VerifiedReconnectHistory,
}
impl<'a> Sources<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn prepare(
        archive: &'a LocalRootPublisher,
        plan: SourcePlan<'a>,
        limits: SourceLimits,
        authority: &'a dyn Authority,
        import_stage: &'static str,
        destination: &ReferenceDeployment,
        cx: &ReplayCx,
        work: &mut WorkBudget<'_>,
    ) -> Result<Self> {
        plan.validate(limits)?;
        if cx.root_dir() != destination.root()
            || archive.root_dir().starts_with(destination.root())
            || destination.root().starts_with(archive.root_dir())
        {
            return Err(Error::Invalid("source and destination roots"));
        }
        authority.check(destination, cx)?;
        let history = VerifiedReconnectHistory::load(
            archive,
            plan.pin,
            limits.history,
            &Access {
                authority,
                destination,
                cx,
            },
            work,
        )?;
        validate_history(plan, limits, &history)?;
        Ok(Self {
            archive,
            plan,
            limits,
            authority,
            import_stage,
            history,
        })
    }

    pub fn history(&self) -> &VerifiedReconnectHistory {
        &self.history
    }

    pub fn import_all<'cx>(
        &self,
        destination: &mut ReferenceDeployment,
        cx: &ReplayCx,
        work: &mut WorkBudget<'cx>,
        framing: &mut DecodeBudget<'cx>,
    ) -> Result<Vec<ImportedGeneration>> {
        let mut generations = Vec::with_capacity(self.plan.bindings.len());
        for (boundary, binding) in self.history.boundaries().iter().zip(self.plan.bindings) {
            cx.checkpoint(self.import_stage)
                .map_err(|_| Error::Denied)?;
            self.authority.check(destination, cx)?;
            let mut generation = ImportedGeneration {
                boundary: boundary.clone(),
                binding: binding.clone(),
                import: None,
            };
            if boundary.prefix().bytes != 0 {
                let request = HttpImportRequest {
                    source: boundary.scope(),
                    pin: boundary.prefix(),
                    sensor: binding.sensor.clone(),
                    stream: binding.stream.clone(),
                    receive_time: binding.receive_time,
                    capture_hint: Some(binding.capture_hint),
                    max_frames: self.limits.maximum_frames_per_generation,
                    max_bytes: self.limits.maximum_bytes_per_generation,
                };
                let access = ImportAccess {
                    authority: self.authority,
                    request: request.digest()?,
                    cx,
                };
                match import_http(
                    self.archive,
                    destination,
                    &request,
                    &access,
                    cx,
                    work,
                    framing,
                ) {
                    Ok(receipt) => generation.import = Some(receipt),
                    Err(HttpImportError::NoCompleteFrames) => {}
                    Err(error) => return Err(error.into()),
                }
            }
            generations.push(generation);
        }
        Ok(generations)
    }

    pub fn revalidate(
        &self,
        destination: &ReferenceDeployment,
        cx: &ReplayCx,
        work: &mut WorkBudget<'_>,
    ) -> Result<()> {
        self.authority.check(destination, cx)?;
        let current = VerifiedReconnectHistory::load(
            self.archive,
            self.plan.pin,
            self.limits.history,
            &Access {
                authority: self.authority,
                destination,
                cx,
            },
            work,
        )?;
        validate_history(self.plan, self.limits, &current)?;
        self.authority.check(destination, cx)
    }
}

fn validate_history(
    plan: SourcePlan<'_>,
    limits: SourceLimits,
    history: &VerifiedReconnectHistory,
) -> Result<()> {
    if history.pin() != plan.pin || history.boundaries().len() != plan.bindings.len() {
        return Err(Error::Invalid("exact complete history inventory"));
    }
    for (boundary, binding) in history.boundaries().iter().zip(plan.bindings) {
        if boundary.scope().stream.generation != binding.generation
            || boundary.prefix().bytes > limits.maximum_bytes_per_generation
            || boundary.totals().frames > limits.maximum_frames_per_generation as u64
        {
            return Err(Error::Invalid("generation mapping or prefix bound"));
        }
    }
    Ok(())
}
