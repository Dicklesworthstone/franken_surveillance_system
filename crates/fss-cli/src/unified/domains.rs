#![forbid(unsafe_code)]
//! Static registry of the unified `fss <domain> <verb>` operational grammar and `fss/1` command
//! metadata.
//!
//! Semantic plane: `"support"` (pure static CLI grammar catalog; no I/O or authority mutation).

/// Flag translation strategy used when delegating a unified `<domain> <verb>` invocation to a
/// companion `fss-*` binary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlagTranslationMode {
    /// Standard pass-through: `--root` is deployment root, `--archive` is capture archive,
    /// `--approve` is approval digest.
    Standard,
    /// Capture-archive command where legacy binary spells the archive directory as `--root`:
    /// unified `--archive` translates to legacy `--root`, and unified `--root` is refused.
    ArchiveAsLegacyRoot,
    /// Backup command where legacy binary spells the pinned manifest digest as `--expect`:
    /// unified `--approve` translates to `--expect`.
    ApproveAsExpect,
    /// UniFi probe command where legacy binary spells the approval digest as `--approval`:
    /// unified `--approve` translates to `--approval`.
    ApproveAsApproval,
    /// Evidence hold mutation command (`fss-hold place|release`) validating canonical `prefix:id`
    /// hold identifiers and resolving `--site` from `--root` when omitted.
    HoldSubcommand,
    /// Retention policy command (`fss-event delete policy-show|policy-plan|policy-commit`) with
    /// sub-action translation (`show`, `plan`, `commit`).
    HoldPolicy,
    /// Certified Graph Atlas dispatch (`fss graph atlas`) delegating to `fss-event graph analyze`.
    GraphAtlas,
    /// Event deletion subcommand (`fss-event delete <sub-action>`).
    EventDelete,
    /// Redacted or review media export (`fss-export <event|show|media|review>`).
    MediaExport,
    /// Privacy mask declaration (`fss-event privacy-mask declare`).
    PrivacyMaskDeclare,
    /// Operator event review (`fss-review <show|investigate|resolve|reject>`).
    PrivacyReview,
    /// Owner-network camera discovery (`fss-discover`) requiring `--json` and `--owner-authorized`.
    Discover,
    /// Media custody subcommands (`fss-file <import|decode|verify>`), forwarding `--json`.
    FileSubcommand,
}

/// Execution backend for a unified `fss <domain> <verb>` command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnifiedBackend {
    /// Handled natively by `crate::site_cmd`.
    InProcessSite,
    /// Handled natively by `crate::migrate_cmd`.
    InProcessMigrate,
    /// Read-only in-process live/retained camera status (`ops_targets::OpsDispatch::Cameras`).
    InProcessCameras,
    /// Read-only in-process Certified Graph Atlas projection (`ops_targets::OpsDispatch::Graph`).
    InProcessGraph {
        /// Default registered projection name (`SensorCoverageGraph`, etc.).
        default_projection: &'static str,
        /// Default registered algorithm identity (`ALG-BRIDGE-001`, etc.).
        default_algorithm: &'static str,
    },
    /// Read-only in-process holds and retention policy listing (`ops_targets::OpsDispatch::Holds`).
    InProcessHolds,
    /// Read-only in-process privacy mask inspection (`ops_targets::OpsDispatch::PrivacyMasks`).
    InProcessPrivacyMasks,
    /// In-process encrypted secret vault CLI (`crate::vault_cmd`).
    InProcessVault,
    /// In-process pure-Rust TLS 1.3 webhook and relay notification CLI (`crate::notify_cmd`).
    InProcessNotify,
    /// In-process AEAD sealed packfile encryption, S3/R2/B2 archival, and crypto-erasure CLI (`crate::pack_archive_cmd`).
    InProcessPackArchive,
    /// Read-only in-process `fss-fusion` when `--root` is provided without `--query`/`--sequence`,
    /// otherwise delegates to the companion `fss-fuse` binary.
    InProcessFusionOrCompanion {
        /// Sibling companion binary name (`fss-fuse`).
        binary: &'static str,
        /// Whether ablation selectors (`--without-sensor`/`--without-domain`) are expected.
        ablation_mode: bool,
    },
    /// Delegates to a sibling companion binary in the executable directory with normalized flags.
    Companion {
        /// Sibling companion binary basename (for example `"fss-file"`).
        binary: &'static str,
        /// Fixed leading subcommand tokens prepended before translated user flags.
        prefix_args: &'static [&'static str],
        /// Flag normalization and translation rule.
        flag_mode: FlagTranslationMode,
        /// Whether the companion binary accepts `--json` directly on argv.
        companion_accepts_json: bool,
    },
}

/// Specification of one documented flag on a unified `<domain> <verb>` command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlagSpec {
    /// Long flag name including leading `--` (for example `"--root"`).
    pub name: &'static str,
    /// Optional value placeholder (for example `Some("<deployment-dir>")`), `None` for bare flags.
    pub value_hint: Option<&'static str>,
    /// Concise human description of the flag semantics.
    pub description: &'static str,
    /// Whether the flag is normally required for execution.
    pub required: bool,
}

/// Complete specification of one verb under a unified operational domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerbSpec {
    /// Parent domain name (for example `"camera"`).
    pub domain: &'static str,
    /// Verb name (for example `"discover"`).
    pub verb: &'static str,
    /// Concise one-line description.
    pub summary: &'static str,
    /// Canonical usage line starting with `fss <domain>`.
    pub usage: &'static str,
    /// Execution backend.
    pub backend: UnifiedBackend,
    /// True when the verb can request or commit an authority/custody mutation (approval-gated).
    pub mutating: bool,
    /// True when preview JSON responses are normalized to guarantee top-level `approval_digest`
    /// and `approve_command`.
    pub normalizes_preview: bool,
    /// True when `--root <deployment-dir>` is accepted as a deployment root.
    pub accepts_root: bool,
    /// True when `--archive <archive-dir>` is accepted as a capture archive directory.
    pub accepts_archive: bool,
    /// Documented flags for this verb (consistent across domains).
    pub flags: &'static [FlagSpec],
}

/// Complete specification of one unified operational domain (`fss <domain> <verb>`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DomainSpec {
    /// Domain name (for example `"camera"`).
    pub name: &'static str,
    /// Concise domain summary.
    pub summary: &'static str,
    /// Ordered list of verbs belonging to this domain.
    pub verbs: &'static [VerbSpec],
}

const fn flag(
    name: &'static str,
    hint: Option<&'static str>,
    desc: &'static str,
    required: bool,
) -> FlagSpec {
    FlagSpec {
        name,
        value_hint: hint,
        description: desc,
        required,
    }
}

const fn comp(
    binary: &'static str,
    prefix_args: &'static [&'static str],
    flag_mode: FlagTranslationMode,
    companion_accepts_json: bool,
) -> UnifiedBackend {
    UnifiedBackend::Companion {
        binary,
        prefix_args,
        flag_mode,
        companion_accepts_json,
    }
}

const F_ROOT: FlagSpec = flag(
    "--root",
    Some("<deployment-dir>"),
    "FSS deployment root directory (never an archive)",
    true,
);
const F_ROOT_OPT: FlagSpec = flag(
    "--root",
    Some("<deployment-dir>"),
    "Optional FSS deployment root directory (never an archive)",
    false,
);
const F_ARCHIVE: FlagSpec = flag(
    "--archive",
    Some("<archive-dir>"),
    "Capture archive directory (distinct from deployment --root)",
    true,
);
const F_SITE: FlagSpec = flag(
    "--site",
    Some("<site-id>"),
    "Site lineage identifier (auto-resolved from --root when omitted)",
    false,
);
const F_APPROVE: FlagSpec = flag(
    "--approve",
    Some("<sha256>"),
    "Exact SHA-256 approval digest from a prior preview",
    false,
);
const F_PRINCIPAL: FlagSpec = flag(
    "--principal",
    Some("<principal-id>"),
    "Audit principal identity (default principal:local-operator)",
    false,
);
const F_JSON: FlagSpec = flag(
    "--json",
    None,
    "Emit deterministic machine-readable JSON output",
    false,
);
const F_HELP: FlagSpec = flag(
    "--help",
    None,
    "Print structured help for this command and exit 0",
    false,
);
const F_MANIFEST: FlagSpec = flag(
    "--manifest",
    Some("<file>"),
    "Path to the site manifest JSON file",
    true,
);
const F_BUNDLE: FlagSpec = flag(
    "--bundle",
    Some("<bundle-dir>"),
    "Local backup bundle directory path",
    true,
);
const F_HOLD_ID: FlagSpec = flag(
    "--hold-id",
    Some("<prefix:id>"),
    "Canonical prefix:id (e.g. hold:front-door-001) or legacy [A-Za-z0-9_-] hold ID",
    true,
);

const FLAGS_JSON_HELP: &[FlagSpec] = &[F_JSON, F_HELP];
const FLAGS_ROOT_SITE_JSON: &[FlagSpec] = &[F_ROOT, F_SITE, F_JSON, F_HELP];
const FLAGS_ROOT_SITE_APPROVE: &[FlagSpec] = &[F_ROOT, F_SITE, F_APPROVE, F_JSON, F_HELP];
const FLAGS_ARCHIVE_ROOT_APPROVE: &[FlagSpec] =
    &[F_ARCHIVE, F_ROOT, F_SITE, F_APPROVE, F_JSON, F_HELP];
const FLAGS_GRAPH_STD: &[FlagSpec] = &[F_ROOT, F_PRINCIPAL, F_JSON, F_HELP];
const FLAGS_ROOT_SITE_PRINCIPAL: &[FlagSpec] = &[F_ROOT, F_SITE, F_PRINCIPAL, F_JSON, F_HELP];
const FLAGS_SITE_ROOT: &[FlagSpec] = &[F_ROOT, F_JSON, F_HELP];

const SITE_VERBS: &[VerbSpec] = &[
    VerbSpec {
        domain: "site",
        verb: "validate",
        summary: "Validate a secret-free site manifest and report its canonical digest",
        usage: "fss site validate --manifest <file> --json [--help]",
        backend: UnifiedBackend::InProcessSite,
        mutating: false,
        normalizes_preview: false,
        accepts_root: false,
        accepts_archive: false,
        flags: &[F_MANIFEST, F_JSON, F_HELP],
    },
    VerbSpec {
        domain: "site",
        verb: "probe",
        summary: "Preview or approve a bounded native RTSP picture observation",
        usage: "fss site probe --manifest <file> --source <id> --codec avc|hevc|jpeg [--approve <sha256>] --json [--help]",
        backend: UnifiedBackend::InProcessSite,
        mutating: true,
        normalizes_preview: true,
        accepts_root: false,
        accepts_archive: false,
        flags: &[F_MANIFEST, F_APPROVE, F_JSON, F_HELP],
    },
    VerbSpec {
        domain: "site",
        verb: "probe-file",
        summary: "Measure recorded DESCRIBE and RTPdump bytes into a probe receipt",
        usage: "fss site probe-file --manifest <file> --source <id> --codec avc|hevc|jpeg --json [--help]",
        backend: UnifiedBackend::InProcessSite,
        mutating: false,
        normalizes_preview: false,
        accepts_root: false,
        accepts_archive: false,
        flags: FLAGS_JSON_HELP,
    },
    VerbSpec {
        domain: "site",
        verb: "plan",
        summary: "Compile atomic native capture plans from a manifest and probe receipts",
        usage: "fss site plan --manifest <file> --probes <file> --archive-root <dir> --pins-root <dir> --epoch <n> --stop-after-pictures <n> --json [--help]",
        backend: UnifiedBackend::InProcessSite,
        mutating: false,
        normalizes_preview: false,
        accepts_root: false,
        accepts_archive: false,
        flags: FLAGS_JSON_HELP,
    },
    VerbSpec {
        domain: "site",
        verb: "run",
        summary: "Run the always-on Asupersync-owned fss-daemon supervisor",
        usage: "fss site run --manifest <site.json> [--root <deployment-dir>] [--vault-dir <dir> --passphrase-file <0600-file>] [--once-ticks <n>] [--tick-ms <n>] [--sensor-health conservative-v1] [--json] [--help]",
        backend: UnifiedBackend::InProcessSite,
        mutating: true,
        normalizes_preview: false,
        accepts_root: true,
        accepts_archive: false,
        flags: &[F_MANIFEST, F_ROOT_OPT, F_JSON, F_HELP],
    },
    VerbSpec {
        domain: "site",
        verb: "status",
        summary: "Query live fss-daemon status over local fss-ipc",
        usage: "fss site status --root <deployment-dir> [--site-id <id>] [--json] [--help]",
        backend: UnifiedBackend::InProcessSite,
        mutating: false,
        normalizes_preview: false,
        accepts_root: true,
        accepts_archive: false,
        flags: FLAGS_SITE_ROOT,
    },
    VerbSpec {
        domain: "site",
        verb: "stop",
        summary: "Request graceful request->drain->finalize shutdown over local fss-ipc",
        usage: "fss site stop --root <deployment-dir> [--site-id <id>] [--json] [--help]",
        backend: UnifiedBackend::InProcessSite,
        mutating: true,
        normalizes_preview: false,
        accepts_root: true,
        accepts_archive: false,
        flags: FLAGS_SITE_ROOT,
    },
];

const CAMERA_VERBS: &[VerbSpec] = &[
    VerbSpec {
        domain: "camera",
        verb: "discover",
        summary: "Discover owner-network cameras via passive beacons and bounded LAN census",
        usage: "fss camera discover --subnet <cidr> --owner-authorized [--root <deployment-dir>] [--site <site-id>] [--json] [--help]",
        backend: comp("fss-discover", &[], FlagTranslationMode::Discover, true),
        mutating: false,
        normalizes_preview: false,
        accepts_root: true,
        accepts_archive: false,
        flags: &[
            flag(
                "--subnet",
                Some("<cidr>"),
                "Owner-authorized LAN subnet CIDR to scan (repeatable)",
                true,
            ),
            flag(
                "--owner-authorized",
                None,
                "Explicit owner authorization attestation for LAN probes",
                true,
            ),
            F_ROOT_OPT,
            F_SITE,
            F_JSON,
            F_HELP,
        ],
    },
    VerbSpec {
        domain: "camera",
        verb: "capture-rtsp",
        summary: "Preview or run an owner-approved bounded native RTSP archive capture",
        usage: "fss camera capture-rtsp --archive <archive-dir> --pins <pins-dir> --peer <ip:port> [--approve <sha256>] [--json] [--help]",
        backend: comp(
            "fss-capture-rtsp",
            &[],
            FlagTranslationMode::ArchiveAsLegacyRoot,
            false,
        ),
        mutating: true,
        normalizes_preview: true,
        accepts_root: false,
        accepts_archive: true,
        flags: &[F_ARCHIVE, F_APPROVE, F_JSON, F_HELP],
    },
    VerbSpec {
        domain: "camera",
        verb: "capture-tutk",
        summary: "Acquire a live owner-authorized TUTK (0xCC51) camera into a deployment",
        usage: "fss camera capture-tutk --root <deployment-dir> --cfg <camera-cfg.json> --owner-authorized [--site <site-id>] [--secs <n>] [--json] [--help]",
        backend: comp(
            "fss-capture-tutk",
            &[],
            FlagTranslationMode::Standard,
            false,
        ),
        mutating: true,
        normalizes_preview: false,
        accepts_root: true,
        accepts_archive: false,
        flags: &[
            F_ROOT,
            flag(
                "--cfg",
                Some("<camera-cfg.json>"),
                "Mode-600 camera secrets configuration file",
                true,
            ),
            F_SITE,
            F_JSON,
            F_HELP,
        ],
    },
    VerbSpec {
        domain: "camera",
        verb: "capture-onvif",
        summary: "Fetch and retain one owner-authorized ONVIF Media1 snapshot",
        usage: "fss camera capture-onvif --root <deployment-dir> --xaddr <url> --sensor-id <id> --stream-id <id> --receive-time-ns <n> --owner-authorized [--json] [--help]",
        backend: comp(
            "fss-capture-onvif",
            &[],
            FlagTranslationMode::Standard,
            false,
        ),
        mutating: true,
        normalizes_preview: true,
        accepts_root: true,
        accepts_archive: false,
        flags: &[F_ROOT, F_APPROVE, F_JSON, F_HELP],
    },
    VerbSpec {
        domain: "camera",
        verb: "probe-unifi",
        summary: "Run a scoped owner-approved UniFi UDP-10001 discovery probe",
        usage: "fss camera probe-unifi (--iface <ipv4> --prefix <1..32> | --auto-scope <cidr>) --principal <id> --approve <sha256> --owner-authorized [--json] [--help]",
        backend: comp(
            "fss-unifi-discover",
            &[],
            FlagTranslationMode::ApproveAsApproval,
            false,
        ),
        mutating: false,
        normalizes_preview: false,
        accepts_root: false,
        accepts_archive: false,
        flags: &[F_PRINCIPAL, F_APPROVE, F_JSON, F_HELP],
    },
    VerbSpec {
        domain: "camera",
        verb: "list",
        summary: "Inspect live daemon camera status with automatic read-only MVCC fallback",
        usage: "fss camera list --root <deployment-dir> [--camera-id <id>] [--site-id <id>] [--principal <id>] [--json] [--help]",
        backend: UnifiedBackend::InProcessCameras,
        mutating: false,
        normalizes_preview: false,
        accepts_root: true,
        accepts_archive: false,
        flags: &[
            F_ROOT,
            flag(
                "--camera-id",
                Some("<sensor-id>"),
                "Filter telemetry to one camera ID",
                false,
            ),
            F_SITE,
            F_PRINCIPAL,
            F_JSON,
            F_HELP,
        ],
    },
];

const MEDIA_VERBS: &[VerbSpec] = &[
    VerbSpec {
        domain: "media",
        verb: "import",
        summary: "Import a local MJPEG, H.264, H.265, MP4, MKV, FLV, or rtpdump file into custody",
        usage: "fss media import --root <deployment-dir> --site <site-id> --input <file> --sensor <id> --stream <id> --receive-time-ns <n> [--json] [--help]",
        backend: comp(
            "fss-file",
            &["import"],
            FlagTranslationMode::FileSubcommand,
            true,
        ),
        mutating: true,
        normalizes_preview: false,
        accepts_root: true,
        accepts_archive: false,
        flags: &[
            F_ROOT,
            F_SITE,
            flag(
                "--input",
                Some("<file>"),
                "Local recorded media file to retain verbatim",
                true,
            ),
            F_JSON,
            F_HELP,
        ],
    },
    VerbSpec {
        domain: "media",
        verb: "import-rtsp",
        summary: "Preview or execute an approved RTSP archive window/catalog import",
        usage: "fss media import-rtsp --archive <archive-dir> --root <deployment-dir> --site <site-id> --codec avc|hevc [--approve <sha256>] [--json] [--help]",
        backend: comp("fss-import-rtsp", &[], FlagTranslationMode::Standard, false),
        mutating: true,
        normalizes_preview: true,
        accepts_root: true,
        accepts_archive: true,
        flags: FLAGS_ARCHIVE_ROOT_APPROVE,
    },
    VerbSpec {
        domain: "media",
        verb: "import-http",
        summary: "Preview or execute an approved HTTP MJPEG archive import",
        usage: "fss media import-http --archive <archive-dir> --root <deployment-dir> --site <site-id> [--approve <sha256>] [--json] [--help]",
        backend: comp("fss-import-http", &[], FlagTranslationMode::Standard, false),
        mutating: true,
        normalizes_preview: true,
        accepts_root: true,
        accepts_archive: true,
        flags: FLAGS_ARCHIVE_ROOT_APPROVE,
    },
    VerbSpec {
        domain: "media",
        verb: "decode",
        summary: "Decode retained source segments under active sensor privacy masks",
        usage: "fss media decode --root <deployment-dir> [--site <site-id>] --import-id <sha256> --segment <n> --interpretation gray|ycbcr [--output <file>] [--json] [--help]",
        backend: comp(
            "fss-file",
            &["decode"],
            FlagTranslationMode::FileSubcommand,
            true,
        ),
        mutating: true,
        normalizes_preview: false,
        accepts_root: true,
        accepts_archive: false,
        flags: FLAGS_ROOT_SITE_JSON,
    },
    VerbSpec {
        domain: "media",
        verb: "verify",
        summary: "Verify retained source custody digests read-only without mutation",
        usage: "fss media verify --root <deployment-dir> [--site <site-id>] --import-id <sha256> [--json] [--help]",
        backend: comp(
            "fss-file",
            &["verify"],
            FlagTranslationMode::FileSubcommand,
            true,
        ),
        mutating: false,
        normalizes_preview: false,
        accepts_root: true,
        accepts_archive: false,
        flags: FLAGS_ROOT_SITE_JSON,
    },
    VerbSpec {
        domain: "media",
        verb: "export",
        summary: "Preview or publish approval-gated redacted event/review exports",
        usage: "fss media export [event|show|media|review] --root <deployment-dir> [--site <site-id>] [--approve <sha256>] [--json] [--help]",
        backend: comp("fss-export", &[], FlagTranslationMode::MediaExport, false),
        mutating: true,
        normalizes_preview: true,
        accepts_root: true,
        accepts_archive: false,
        flags: FLAGS_ROOT_SITE_APPROVE,
    },
];

const INFER_VERBS: &[VerbSpec] = &[
    VerbSpec {
        domain: "infer",
        verb: "activity",
        summary: "Run the pinned scalar activity model over two retained frames",
        usage: "fss infer activity --root <deployment-dir> [--site <site-id>] --import-id <sha256> --reference-segment <n> --segment <n> [--json] [--help]",
        backend: comp(
            "fss-infer",
            &["activity"],
            FlagTranslationMode::Standard,
            false,
        ),
        mutating: true,
        normalizes_preview: false,
        accepts_root: true,
        accepts_archive: false,
        flags: FLAGS_ROOT_SITE_JSON,
    },
    VerbSpec {
        domain: "infer",
        verb: "package-detect",
        summary: "Run a digest-pinned verified RGB detector package over retained frames",
        usage: "fss infer package-detect --root <deployment-dir> [--site <site-id>] --import-id <sha256> --first-segment <n> --frames <n> --package <file> --package-digest <sha256> --interpretation gray|ycbcr [--json] [--help]",
        backend: comp(
            "fss-infer",
            &["package-detect"],
            FlagTranslationMode::Standard,
            false,
        ),
        mutating: false,
        normalizes_preview: false,
        accepts_root: true,
        accepts_archive: false,
        flags: FLAGS_ROOT_SITE_JSON,
    },
    VerbSpec {
        domain: "infer",
        verb: "profile",
        summary: "Execute bounded recording-to-report scalar model analysis with MAC/tensor budgets",
        usage: "fss infer profile --root <deployment-dir> [--site <site-id>] --import-id <sha256> --first-segment <n> --frames <n> --model-digest <sha256> [--json] [--help]",
        backend: comp(
            "fss-infer",
            &["analyze"],
            FlagTranslationMode::Standard,
            false,
        ),
        mutating: true,
        normalizes_preview: false,
        accepts_root: true,
        accepts_archive: false,
        flags: FLAGS_ROOT_SITE_JSON,
    },
];

const EVENT_VERBS: &[VerbSpec] = &[
    VerbSpec {
        domain: "event",
        verb: "watch",
        summary: "Run single-camera foreground/tracker/cascade watch over retained recordings",
        usage: "fss event watch --root <deployment-dir> [--site <site-id>] --import-id <sha256> --interpretation gray|ycbcr --zone <id:x,y,w,h> [--approve <sha256>] [--json] [--help]",
        backend: comp(
            "fss-event",
            &["watch"],
            FlagTranslationMode::Standard,
            false,
        ),
        mutating: true,
        normalizes_preview: true,
        accepts_root: true,
        accepts_archive: false,
        flags: FLAGS_ROOT_SITE_APPROVE,
    },
    VerbSpec {
        domain: "event",
        verb: "read",
        summary: "Read and verify a committed event record from retained custody",
        usage: "fss event read --root <deployment-dir> [--site <site-id>] --event-id <id> [--json] [--help]",
        backend: comp("fss-event", &["read"], FlagTranslationMode::Standard, false),
        mutating: false,
        normalizes_preview: false,
        accepts_root: true,
        accepts_archive: false,
        flags: &[
            F_ROOT,
            F_SITE,
            flag(
                "--event-id",
                Some("<event-id>"),
                "Committed event identifier to inspect",
                true,
            ),
            F_JSON,
            F_HELP,
        ],
    },
    VerbSpec {
        domain: "event",
        verb: "detect-osd",
        summary: "Detect corner/edge OSD overlay candidates read-only without activating them",
        usage: "fss event detect-osd --root <deployment-dir> [--site <site-id>] --import-id <sha256> --interpretation gray|ycbcr [--json] [--help]",
        backend: comp(
            "fss-event",
            &["detect-osd"],
            FlagTranslationMode::Standard,
            false,
        ),
        mutating: false,
        normalizes_preview: false,
        accepts_root: true,
        accepts_archive: false,
        flags: FLAGS_ROOT_SITE_JSON,
    },
    VerbSpec {
        domain: "event",
        verb: "corroborate",
        summary: "Associate two independent camera recordings with shared failure domains",
        usage: "fss event corroborate --root <deployment-dir> [--site <site-id>] --camera <name:sha256> --camera <name:sha256> [--approve <sha256>] [--json] [--help]",
        backend: comp(
            "fss-event",
            &["corroborate"],
            FlagTranslationMode::Standard,
            false,
        ),
        mutating: true,
        normalizes_preview: true,
        accepts_root: true,
        accepts_archive: false,
        flags: FLAGS_ROOT_SITE_APPROVE,
    },
    VerbSpec {
        domain: "event",
        verb: "alert",
        summary: "Preview, prepare, or dispatch an approved single webhook alert",
        usage: "fss event alert --root <deployment-dir> [--site <site-id>] --event-id <id> --relay <ip:port> --path </path> --plaintext-approval <sha256> --deadline-ms <n> [--approve <sha256>] [--json] [--help]",
        backend: comp(
            "fss-event",
            &["alert"],
            FlagTranslationMode::Standard,
            false,
        ),
        mutating: true,
        normalizes_preview: true,
        accepts_root: true,
        accepts_archive: false,
        flags: FLAGS_ROOT_SITE_APPROVE,
    },
    VerbSpec {
        domain: "event",
        verb: "delete",
        summary: "Plan or commit graph-complete, hold-enforced local evidence deletion",
        usage: "fss event delete <plan|commit|retention-plan|retention-commit> --root <deployment-dir> [--site <site-id>] [--approve <sha256>] [--json] [--help]",
        backend: comp(
            "fss-event",
            &["delete"],
            FlagTranslationMode::EventDelete,
            false,
        ),
        mutating: true,
        normalizes_preview: true,
        accepts_root: true,
        accepts_archive: false,
        flags: FLAGS_ROOT_SITE_APPROVE,
    },
];

const FUSE_VERBS: &[VerbSpec] = &[
    VerbSpec {
        domain: "fuse",
        verb: "evaluate",
        summary: "Evaluate calibrated evidence fusion over a deployment root or query file",
        usage: "fss fuse evaluate (--root <deployment-dir> [--event-id <id>] | --query <query.json>) [--json] [--help]",
        backend: UnifiedBackend::InProcessFusionOrCompanion {
            binary: "fss-fuse",
            ablation_mode: false,
        },
        mutating: false,
        normalizes_preview: false,
        accepts_root: true,
        accepts_archive: false,
        flags: &[F_ROOT_OPT, F_PRINCIPAL, F_JSON, F_HELP],
    },
    VerbSpec {
        domain: "fuse",
        verb: "ablate",
        summary: "Run simultaneous sensor/domain source-loss counterfactual ablation",
        usage: "fss fuse ablate (--root <deployment-dir> | --query <query.json>) [--without-sensor <id>] [--without-domain <domain>] [--json] [--help]",
        backend: UnifiedBackend::InProcessFusionOrCompanion {
            binary: "fss-fuse",
            ablation_mode: true,
        },
        mutating: false,
        normalizes_preview: false,
        accepts_root: true,
        accepts_archive: false,
        flags: &[
            F_ROOT_OPT,
            flag(
                "--without-sensor",
                Some("<sensor-id>"),
                "Exclude a sensor in simultaneous counterfactual ablation",
                false,
            ),
            flag(
                "--without-domain",
                Some("<domain>"),
                "Exclude a failure domain in counterfactual ablation",
                false,
            ),
            F_JSON,
            F_HELP,
        ],
    },
    VerbSpec {
        domain: "fuse",
        verb: "profile",
        summary: "Author an offline digest-pinned event class fusion profile from labelled counts",
        usage: "fss fuse profile --scope watch|dwell|corroborate --counts-digest <sha256> --analysis-digest <sha256> --detector-recipe-digest <sha256> --analysis-roots <sha256,...> [--json] [--help]",
        backend: comp(
            "fss-fusion-profile",
            &[],
            FlagTranslationMode::Standard,
            false,
        ),
        mutating: false,
        normalizes_preview: false,
        accepts_root: false,
        accepts_archive: false,
        flags: &[F_PRINCIPAL, F_JSON, F_HELP],
    },
    VerbSpec {
        domain: "fuse",
        verb: "scene",
        summary: "Reconstruct source-linked multi-camera 3D scene hypotheses against a twin",
        usage: "fss fuse scene [subcommand] [--root <deployment-dir>] [--json] [--help]",
        backend: comp("fss-scene-fuse", &[], FlagTranslationMode::Standard, false),
        mutating: false,
        normalizes_preview: false,
        accepts_root: true,
        accepts_archive: false,
        flags: &[F_ROOT_OPT, F_JSON, F_HELP],
    },
];

const GRAPH_VERBS: &[VerbSpec] = &[
    VerbSpec {
        domain: "graph",
        verb: "coverage",
        summary: "Analyze SensorCoverageGraph single points of failure with ALG-BRIDGE-001",
        usage: "fss graph coverage --root <deployment-dir> [--algorithm ALG-BRIDGE-001|ALG-SCC-001|ALG-COMM-001] [--principal <id>] [--json] [--help]",
        backend: UnifiedBackend::InProcessGraph {
            default_projection: "SensorCoverageGraph",
            default_algorithm: "ALG-BRIDGE-001",
        },
        mutating: false,
        normalizes_preview: false,
        accepts_root: true,
        accepts_archive: false,
        flags: FLAGS_GRAPH_STD,
    },
    VerbSpec {
        domain: "graph",
        verb: "claims",
        summary: "Analyze EvidenceClaimGraph support and contradiction structure",
        usage: "fss graph claims --root <deployment-dir> [--algorithm ALG-BRIDGE-001|ALG-SCC-001|ALG-COMM-001] [--principal <id>] [--json] [--help]",
        backend: UnifiedBackend::InProcessGraph {
            default_projection: "EvidenceClaimGraph",
            default_algorithm: "ALG-BRIDGE-001",
        },
        mutating: false,
        normalizes_preview: false,
        accepts_root: true,
        accepts_archive: false,
        flags: FLAGS_GRAPH_STD,
    },
    VerbSpec {
        domain: "graph",
        verb: "failures",
        summary: "Analyze DeviceFailureGraph shared failure-domain coupling",
        usage: "fss graph failures --root <deployment-dir> [--algorithm ALG-COMM-001|ALG-BRIDGE-001|ALG-SCC-001] [--principal <id>] [--json] [--help]",
        backend: UnifiedBackend::InProcessGraph {
            default_projection: "DeviceFailureGraph",
            default_algorithm: "ALG-COMM-001",
        },
        mutating: false,
        normalizes_preview: false,
        accepts_root: true,
        accepts_archive: false,
        flags: FLAGS_GRAPH_STD,
    },
    VerbSpec {
        domain: "graph",
        verb: "obligations",
        summary: "Analyze PlanObligationGraph active effect and obligation dependencies",
        usage: "fss graph obligations --root <deployment-dir> [--algorithm ALG-SCC-001|ALG-BRIDGE-001|ALG-COMM-001] [--principal <id>] [--json] [--help]",
        backend: UnifiedBackend::InProcessGraph {
            default_projection: "PlanObligationGraph",
            default_algorithm: "ALG-SCC-001",
        },
        mutating: false,
        normalizes_preview: false,
        accepts_root: true,
        accepts_archive: false,
        flags: FLAGS_GRAPH_STD,
    },
    VerbSpec {
        domain: "graph",
        verb: "atlas",
        summary: "Execute any registered Certified Graph Atlas projection and algorithm",
        usage: "fss graph atlas --root <deployment-dir> [--site <site-id>] --projection <graph> --algorithm <alg-id> [--json] [--help]",
        backend: comp(
            "fss-event",
            &["graph", "analyze"],
            FlagTranslationMode::GraphAtlas,
            false,
        ),
        mutating: false,
        normalizes_preview: false,
        accepts_root: true,
        accepts_archive: false,
        flags: &[
            F_ROOT,
            F_SITE,
            flag(
                "--projection",
                Some("<graph-kind>"),
                "Registered graph projection name",
                true,
            ),
            flag(
                "--algorithm",
                Some("<alg-id>"),
                "Registered Certified Graph Atlas algorithm ID",
                true,
            ),
            F_JSON,
            F_HELP,
        ],
    },
];

const HOLD_VERBS: &[VerbSpec] = &[
    VerbSpec {
        domain: "hold",
        verb: "list",
        summary: "List active and terminal legal holds and retention policies read-only",
        usage: "fss hold list --root <deployment-dir> [--sensor <id>] [--attested-now-ns <earliest:latest>] [--principal <id>] [--json] [--help]",
        backend: UnifiedBackend::InProcessHolds,
        mutating: false,
        normalizes_preview: false,
        accepts_root: true,
        accepts_archive: false,
        flags: FLAGS_ROOT_SITE_PRINCIPAL,
    },
    VerbSpec {
        domain: "hold",
        verb: "place",
        summary: "Preview or commit an evidence preservation hold (supports canonical prefix:id)",
        usage: "fss hold place --root <deployment-dir> [--site <site-id>] --hold-id <prefix:id> --import-id <sha256> --reason <text> [--approve <sha256>] [--json] [--help]",
        backend: comp(
            "fss-hold",
            &["place"],
            FlagTranslationMode::HoldSubcommand,
            true,
        ),
        mutating: true,
        normalizes_preview: true,
        accepts_root: true,
        accepts_archive: false,
        flags: &[
            F_ROOT,
            F_SITE,
            F_HOLD_ID,
            flag(
                "--import-id",
                Some("<sha256>"),
                "Exact SHA-256 identity of the retained import",
                true,
            ),
            flag(
                "--reason",
                Some("<text>"),
                "Non-secret operator rationale for the hold",
                true,
            ),
            F_APPROVE,
            F_JSON,
            F_HELP,
        ],
    },
    VerbSpec {
        domain: "hold",
        verb: "release",
        summary: "Preview or commit explicit release of an active preservation hold",
        usage: "fss hold release --root <deployment-dir> [--site <site-id>] --hold-id <prefix:id> --import-id <sha256> --reason <text> [--approve <sha256>] [--json] [--help]",
        backend: comp(
            "fss-hold",
            &["release"],
            FlagTranslationMode::HoldSubcommand,
            true,
        ),
        mutating: true,
        normalizes_preview: true,
        accepts_root: true,
        accepts_archive: false,
        flags: &[F_ROOT, F_SITE, F_HOLD_ID, F_APPROVE, F_JSON, F_HELP],
    },
    VerbSpec {
        domain: "hold",
        verb: "policy",
        summary: "Show, plan, or commit per-sensor bounded retention policies",
        usage: "fss hold policy [show|plan|commit] --root <deployment-dir> [--site <site-id>] [--approve <sha256>] [--json] [--help]",
        backend: comp(
            "fss-event",
            &["delete"],
            FlagTranslationMode::HoldPolicy,
            false,
        ),
        mutating: true,
        normalizes_preview: true,
        accepts_root: true,
        accepts_archive: false,
        flags: FLAGS_ROOT_SITE_APPROVE,
    },
];

const PRIVACY_VERBS: &[VerbSpec] = &[
    VerbSpec {
        domain: "privacy",
        verb: "list",
        summary: "Inspect current retained privacy mask bindings read-only",
        usage: "fss privacy list --root <deployment-dir> [--sensor <id>] [--principal <id>] [--json] [--help]",
        backend: UnifiedBackend::InProcessPrivacyMasks,
        mutating: false,
        normalizes_preview: false,
        accepts_root: true,
        accepts_archive: false,
        flags: FLAGS_ROOT_SITE_PRINCIPAL,
    },
    VerbSpec {
        domain: "privacy",
        verb: "set-mask",
        summary: "Preview or declare a per-sensor pixel redaction mask policy",
        usage: "fss privacy set-mask --root <deployment-dir> [--site <site-id>] --sensor <id> --resolution <WxH> --rect <X,Y,W,H> [--approve <sha256>] [--json] [--help]",
        backend: comp(
            "fss-event",
            &["privacy-mask", "declare"],
            FlagTranslationMode::PrivacyMaskDeclare,
            false,
        ),
        mutating: true,
        normalizes_preview: true,
        accepts_root: true,
        accepts_archive: false,
        flags: FLAGS_ROOT_SITE_APPROVE,
    },
    VerbSpec {
        domain: "privacy",
        verb: "review",
        summary: "Show or transition owner event review dispositions with exact approval",
        usage: "fss privacy review [show|investigate|resolve|reject] --root <deployment-dir> [--site <site-id>] --event-id <id> [--approve <sha256>] [--json] [--help]",
        backend: comp("fss-review", &[], FlagTranslationMode::PrivacyReview, false),
        mutating: true,
        normalizes_preview: true,
        accepts_root: true,
        accepts_archive: false,
        flags: FLAGS_ROOT_SITE_APPROVE,
    },
];

const BACKUP_VERBS: &[VerbSpec] = &[
    VerbSpec {
        domain: "backup",
        verb: "plan",
        summary: "Compute an independent backup manifest digest without modifying the deployment",
        usage: "fss backup plan --root <deployment-dir> --allow-originals [--json] [--help]",
        backend: comp("fss-backup", &["plan"], FlagTranslationMode::Standard, true),
        mutating: false,
        normalizes_preview: true,
        accepts_root: true,
        accepts_archive: false,
        flags: &[
            F_ROOT,
            flag(
                "--allow-originals",
                None,
                "Explicitly grant local original-evidence custody access",
                true,
            ),
            F_JSON,
            F_HELP,
        ],
    },
    VerbSpec {
        domain: "backup",
        verb: "create",
        summary: "Create a manifest-pinned local backup bundle from a quiescent deployment",
        usage: "fss backup create --root <deployment-dir> --bundle <new-bundle-dir> --approve <sha256> --allow-originals [--json] [--help]",
        backend: comp(
            "fss-backup",
            &["create"],
            FlagTranslationMode::ApproveAsExpect,
            true,
        ),
        mutating: true,
        normalizes_preview: false,
        accepts_root: true,
        accepts_archive: false,
        flags: &[F_ROOT, F_BUNDLE, F_APPROVE, F_JSON, F_HELP],
    },
    VerbSpec {
        domain: "backup",
        verb: "inspect",
        summary: "Verify a local backup bundle against its pinned manifest digest",
        usage: "fss backup inspect --bundle <bundle-dir> --approve <sha256> --allow-originals [--json] [--help]",
        backend: comp(
            "fss-backup",
            &["inspect"],
            FlagTranslationMode::ApproveAsExpect,
            true,
        ),
        mutating: false,
        normalizes_preview: false,
        accepts_root: false,
        accepts_archive: false,
        flags: &[F_BUNDLE, F_APPROVE, F_JSON, F_HELP],
    },
    VerbSpec {
        domain: "backup",
        verb: "restore",
        summary: "Restore a verified backup bundle into a fresh deployment root with alert fence",
        usage: "fss backup restore --bundle <bundle-dir> --root <deployment-dir> --approve <sha256> --allow-originals [--json] [--help]",
        backend: comp(
            "fss-backup",
            &["restore"],
            FlagTranslationMode::ApproveAsExpect,
            true,
        ),
        mutating: true,
        normalizes_preview: false,
        accepts_root: true,
        accepts_archive: false,
        flags: &[F_ROOT, F_BUNDLE, F_APPROVE, F_JSON, F_HELP],
    },
];

const MIGRATE_VERBS: &[VerbSpec] = &[VerbSpec {
    domain: "migrate",
    verb: "v1-to-v2",
    summary: "Upgrade a v1 deployment out-of-place into a fresh v2 root with equivalence receipt",
    usage: "fss migrate --from <v1-root> --to <new-v2-root> [--json] [--progress-jsonl] [--help]",
    backend: UnifiedBackend::InProcessMigrate,
    mutating: true,
    normalizes_preview: false,
    accepts_root: false,
    accepts_archive: false,
    flags: &[
        flag(
            "--from",
            Some("<v1-root>"),
            "Existing v1 deployment root read strictly read-only",
            true,
        ),
        flag(
            "--to",
            Some("<new-v2-root>"),
            "Fresh non-existent destination directory for v2",
            true,
        ),
        F_JSON,
        F_HELP,
    ],
}];

const VAULT_VERBS: &[VerbSpec] = &[
    VerbSpec {
        domain: "vault",
        verb: "init",
        summary: "Initialize a new 0700/0600 encrypted local secret vault with zero argv secrets",
        usage: "fss vault init --vault-dir <dir> (--passphrase-file <0600-file> | --passphrase-stdin) [--json] [--help]",
        backend: UnifiedBackend::InProcessVault,
        mutating: true,
        normalizes_preview: false,
        accepts_root: false,
        accepts_archive: false,
        flags: &[
            flag(
                "--vault-dir",
                Some("<dir>"),
                "Target vault directory (created 0700)",
                true,
            ),
            flag(
                "--passphrase-file",
                Some("<0600-file>"),
                "Mode-0600 file supplying vault passphrase",
                false,
            ),
            F_JSON,
            F_HELP,
        ],
    },
    VerbSpec {
        domain: "vault",
        verb: "set",
        summary: "Store or rotate a scope-bound secret from a mode-0600 file or stdin (zero plaintext output)",
        usage: "fss vault set --vault-dir <dir> --secret-id <id> --family <fam> --target <id> --endpoint <scope> (--passphrase-file <0600-file> | --passphrase-stdin) (--secret-file <0600-file> | --secret-stdin) [--json] [--help]",
        backend: UnifiedBackend::InProcessVault,
        mutating: true,
        normalizes_preview: false,
        accepts_root: false,
        accepts_archive: false,
        flags: &[
            flag(
                "--vault-dir",
                Some("<dir>"),
                "Encrypted vault directory",
                true,
            ),
            flag(
                "--secret-id",
                Some("<id>"),
                "Canonical non-secret vault secret identifier",
                true,
            ),
            flag(
                "--family",
                Some("<adapter-family>"),
                "Exact adapter family (rtsp, tutk, alert_webhook, alert_relay, storage_kek, archive_s3, ...)",
                true,
            ),
            F_JSON,
            F_HELP,
        ],
    },
    VerbSpec {
        domain: "vault",
        verb: "list",
        summary: "List stored secret handles and scopes without exposing any plaintext bytes",
        usage: "fss vault list --vault-dir <dir> (--passphrase-file <0600-file> | --passphrase-stdin) [--json] [--help]",
        backend: UnifiedBackend::InProcessVault,
        mutating: false,
        normalizes_preview: false,
        accepts_root: false,
        accepts_archive: false,
        flags: &[
            flag(
                "--vault-dir",
                Some("<dir>"),
                "Encrypted vault directory",
                true,
            ),
            F_JSON,
            F_HELP,
        ],
    },
    VerbSpec {
        domain: "vault",
        verb: "revoke",
        summary: "Revoke a stored secret handle so future adapter fetches fail closed",
        usage: "fss vault revoke --vault-dir <dir> --secret-id <id> (--passphrase-file <0600-file> | --passphrase-stdin) [--json] [--help]",
        backend: UnifiedBackend::InProcessVault,
        mutating: true,
        normalizes_preview: false,
        accepts_root: false,
        accepts_archive: false,
        flags: &[
            flag(
                "--vault-dir",
                Some("<dir>"),
                "Encrypted vault directory",
                true,
            ),
            flag(
                "--secret-id",
                Some("<id>"),
                "Vault secret identifier to revoke",
                true,
            ),
            F_JSON,
            F_HELP,
        ],
    },
    VerbSpec {
        domain: "vault",
        verb: "doctor",
        summary: "Inspect vault directory/file permissions and header integrity read-only",
        usage: "fss vault doctor --vault-dir <dir> [--json] [--help]",
        backend: UnifiedBackend::InProcessVault,
        mutating: false,
        normalizes_preview: false,
        accepts_root: false,
        accepts_archive: false,
        flags: &[
            flag(
                "--vault-dir",
                Some("<dir>"),
                "Encrypted vault directory to inspect",
                true,
            ),
            F_JSON,
            F_HELP,
        ],
    },
];

const NOTIFY_VERBS: &[VerbSpec] = &[
    VerbSpec {
        domain: "notify",
        verb: "preview",
        summary: "Validate a TLS 1.3 webhook/relay target and emit its canonical approval digest (zero network I/O)",
        usage: "fss notify preview --channel <https-webhook|ntfy|pushover|smtps|smtp-starttls> --target-id <id> --secret-id <id> --operation-id <id> --idempotency-key <key> (--ca-pem <file> | --pin-spki <sha256>) [--url <https://...>] [--json] [--help]",
        backend: UnifiedBackend::InProcessNotify,
        mutating: false,
        normalizes_preview: true,
        accepts_root: true,
        accepts_archive: false,
        flags: &[
            flag(
                "--channel",
                Some("<kind>"),
                "Outbound channel: https-webhook, ntfy, pushover, smtps, or smtp-starttls",
                true,
            ),
            flag("--target-id", Some("<id>"), "Operator target label", true),
            flag(
                "--secret-id",
                Some("<id>"),
                "Vault secret identifier for HMAC/bearer/auth credentials",
                true,
            ),
            F_ROOT_OPT,
            F_JSON,
            F_HELP,
        ],
    },
    VerbSpec {
        domain: "notify",
        verb: "dispatch",
        summary: "Dispatch an approved pure-Rust TLS 1.3 notification through the idempotent durable effect journal",
        usage: "fss notify dispatch --channel <https-webhook|ntfy|pushover|smtps|smtp-starttls> --target-id <id> --secret-id <id> --operation-id <id> --idempotency-key <key> --approve <sha256> --vault-dir <dir> --passphrase-file <0600-file> (--ca-pem <file> | --pin-spki <sha256>) [--root <deployment-dir>] [--json] [--help]",
        backend: UnifiedBackend::InProcessNotify,
        mutating: true,
        normalizes_preview: false,
        accepts_root: true,
        accepts_archive: false,
        flags: &[
            flag(
                "--channel",
                Some("<kind>"),
                "Outbound channel: https-webhook, ntfy, pushover, smtps, or smtp-starttls",
                true,
            ),
            flag("--target-id", Some("<id>"), "Operator target label", true),
            flag("--secret-id", Some("<id>"), "Vault secret identifier", true),
            F_APPROVE,
            F_ROOT_OPT,
            F_JSON,
            F_HELP,
        ],
    },
];

const ARCHIVE_VERBS: &[VerbSpec] = &[
    VerbSpec {
        domain: "archive",
        verb: "seal",
        summary: "Seal the active deployment packfile or encrypt a sealed .fssp pack into ChaCha20-Poly1305 .fsep",
        usage: "fss archive seal (--root <deployment-dir> | --packs-dir <dir> --pack-id <epoch:seq> --out <file.fsep> --key-catalog <file.fskc> --vault-dir <dir> --passphrase-file <0600-file> --kek-secret-id <id>) [--json] [--help]",
        backend: UnifiedBackend::InProcessPackArchive,
        mutating: true,
        normalizes_preview: false,
        accepts_root: true,
        accepts_archive: false,
        flags: &[F_ROOT_OPT, F_SITE, F_JSON, F_HELP],
    },
    VerbSpec {
        domain: "archive",
        verb: "verify",
        summary: "Verify a sealed .fssp packfile read-only or authenticate/decrypt an encrypted .fsep pack",
        usage: "fss archive verify --pack-id <epoch:seq> (--root <deployment-dir> | --packs-dir <dir> | --enc-file <file.fsep> --key-catalog <file.fskc> --vault-dir <dir> --passphrase-file <0600-file> --kek-secret-id <id>) [--json] [--help]",
        backend: UnifiedBackend::InProcessPackArchive,
        mutating: false,
        normalizes_preview: false,
        accepts_root: true,
        accepts_archive: false,
        flags: &[F_ROOT_OPT, F_SITE, F_JSON, F_HELP],
    },
    VerbSpec {
        domain: "archive",
        verb: "upload",
        summary: "Preview or execute encrypted whole-pack S3/R2/B2 archival with root-last manifest publication",
        usage: "fss archive upload --pack-id <epoch:seq> --peer <ip:port> --host <host> --bucket <name> [--root <deployment-dir>] [--approve <sha256>] [--json] [--help]",
        backend: UnifiedBackend::InProcessPackArchive,
        mutating: true,
        normalizes_preview: true,
        accepts_root: true,
        accepts_archive: false,
        flags: &[F_ROOT_OPT, F_SITE, F_APPROVE, F_JSON, F_HELP],
    },
    VerbSpec {
        domain: "archive",
        verb: "restore",
        summary: "Recover a cold archive from a local or independently pinned remote manifest, then decrypt and verify its packfile",
        usage: "fss archive restore (--manifest-file <pack.manifest.fssc> | --manifest-object-key <key> --expected-manifest <sha256>) --key-catalog <file.fskc> --peer <ip:port> --host <host> --bucket <name> --vault-dir <dir> --passphrase-file <0600-file> --kek-secret-id <id> --s3-secret-id <id> --access-key-id <id> (--packs-dir <dir> | --root <deployment-dir>) [--json] [--help]",
        backend: UnifiedBackend::InProcessPackArchive,
        mutating: true,
        normalizes_preview: false,
        accepts_root: true,
        accepts_archive: false,
        flags: &[
            flag(
                "--manifest-file",
                Some("<file>"),
                "Local archive manifest",
                false,
            ),
            flag(
                "--manifest-object-key",
                Some("<key>"),
                "Remote root manifest from the upload receipt",
                false,
            ),
            flag(
                "--expected-manifest",
                Some("<sha256>"),
                "Independently retained manifest_digest for remote recovery",
                false,
            ),
            F_ROOT_OPT,
            F_SITE,
            F_JSON,
            F_HELP,
        ],
    },
    VerbSpec {
        domain: "archive",
        verb: "crypto-erase",
        summary: "Preview or permanently destroy a wrapped DEK envelope with a KEK-signed erasure receipt (PRIV-010)",
        usage: "fss archive crypto-erase --key-catalog <file.fskc> --dek-id <32-hex> [--reason <text>] [--approve <sha256>] [--vault-dir <dir> --passphrase-file <0600-file> --kek-secret-id <id>] [--json] [--help]",
        backend: UnifiedBackend::InProcessPackArchive,
        mutating: true,
        normalizes_preview: true,
        accepts_root: false,
        accepts_archive: false,
        flags: &[F_SITE, F_APPROVE, F_JSON, F_HELP],
    },
];

/// Complete static catalog of all 14 unified operational domains.
pub const UNIFIED_DOMAINS: &[DomainSpec] = &[
    DomainSpec {
        name: "site",
        summary: "Site manifest validation, probing, capture planning, and local daemon control",
        verbs: SITE_VERBS,
    },
    DomainSpec {
        name: "camera",
        summary: "Owner-network camera discovery, live capture adapters, and camera inventory",
        verbs: CAMERA_VERBS,
    },
    DomainSpec {
        name: "media",
        summary: "Source-preserving media import, archive ingestion, decoding, verification, and export",
        verbs: MEDIA_VERBS,
    },
    DomainSpec {
        name: "infer",
        summary: "Deterministic pure-Rust scalar inference, activity scoring, and detector packages",
        verbs: INFER_VERBS,
    },
    DomainSpec {
        name: "event",
        summary: "Watch scanning, OSD detection, corroboration, alerts, reading, and deletion",
        verbs: EVENT_VERBS,
    },
    DomainSpec {
        name: "fuse",
        summary: "Calibrated milliban LLR fusion, counterfactual ablations, profiles, and 3D scene fusion",
        verbs: FUSE_VERBS,
    },
    DomainSpec {
        name: "graph",
        summary: "Certified Graph Atlas structural analysis with verified complexity witnesses",
        verbs: GRAPH_VERBS,
    },
    DomainSpec {
        name: "hold",
        summary: "Evidence preservation holds and per-sensor retention policy governance",
        verbs: HOLD_VERBS,
    },
    DomainSpec {
        name: "privacy",
        summary: "Per-sensor privacy masks and owner event review workflows",
        verbs: PRIVACY_VERBS,
    },
    DomainSpec {
        name: "backup",
        summary: "Quiescent local deployment backup planning, creation, verification, and restore",
        verbs: BACKUP_VERBS,
    },
    DomainSpec {
        name: "migrate",
        summary: "Non-destructive out-of-place v1-to-v2 deployment upgrader",
        verbs: MIGRATE_VERBS,
    },
    DomainSpec {
        name: "vault",
        summary: "Zero-plaintext encrypted local secret vault with scope-bound adapter credentials",
        verbs: VAULT_VERBS,
    },
    DomainSpec {
        name: "notify",
        summary: "Pure-Rust RFC 8446 TLS 1.3 HMAC webhooks and multi-channel relays (ntfy, Pushover, SMTP)",
        verbs: NOTIFY_VERBS,
    },
    DomainSpec {
        name: "archive",
        summary: "ChaCha20-Poly1305 AEAD pack encryption, S3/R2/B2 cold archival, restore, and crypto-erasure",
        verbs: ARCHIVE_VERBS,
    },
];

/// Looks up a domain specification by its canonical name.
#[must_use]
pub fn find_domain(name: &str) -> Option<&'static DomainSpec> {
    UNIFIED_DOMAINS.iter().find(|domain| domain.name == name)
}

/// Looks up a verb specification by `(domain, verb)`.
#[must_use]
pub fn find_verb(domain: &str, verb: &str) -> Option<&'static VerbSpec> {
    find_domain(domain)?
        .verbs
        .iter()
        .find(|entry| entry.verb == verb)
}

/// Returns `true` when `name` is one of the 12 routed unified operational domains handled via
/// `FssCommand::Unified` (excluding `site` and `migrate`, which keep their dedicated `FssCommand`
/// variants for full backward compatibility).
#[must_use]
pub fn is_routed_unified_domain(name: &str) -> bool {
    matches!(
        name,
        "camera"
            | "media"
            | "infer"
            | "event"
            | "fuse"
            | "graph"
            | "hold"
            | "privacy"
            | "backup"
            | "vault"
            | "notify"
            | "archive"
    )
}
