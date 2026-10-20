#![forbid(unsafe_code)]
//! Pure, opt-in bounds for a local, explicitly unredacted media projection.

use std::collections::BTreeMap;

use fss_cli::agent_json::{object, string};
use fss_reference::rtsp::preview::PreviewLimits;

pub(crate) const POLICY: &str = "local-unredacted-preview:v1:loopback-only:ephemeral-token:\
durable-idr-windows:bounded-shared-ring:disconnect-slow-readers:no-transcode:no-custody-authority";
pub(crate) const MAX_HEADER_BYTES: usize = 8192;
pub(crate) const IO_BYTES: usize = 16 * 1024;
pub(crate) const CLIENT_LEASE_NS: u64 = 5_000_000_000;
pub(crate) const MAX_SUBSCRIPTIONS: u64 = 256;

#[derive(Clone, Debug)]
pub(crate) struct PreviewPlan {
    pub(crate) port: u16,
    pub(crate) limits: PreviewLimits,
}

impl PreviewPlan {
    pub(crate) fn parse(values: &BTreeMap<&str, &str>) -> Result<Option<Self>, &'static str> {
        const KEYS: [&str; 7] = [
            "--allow-local-unredacted-preview",
            "--preview-max-clients",
            "--preview-max-bytes",
            "--preview-max-fragment-bytes",
            "--preview-max-output-bytes",
            "--preview-max-age-ms",
            "--preview-port",
        ];
        if !values.contains_key("--preview-port") {
            return if KEYS.iter().any(|key| values.contains_key(key)) {
                Err("preview bounds and permission require --preview-port")
            } else {
                Ok(None)
            };
        }
        if values.get("--allow-local-unredacted-preview") != Some(&"yes") {
            return Err("live preview requires --allow-local-unredacted-preview yes");
        }
        let number = |key: &str, default: u64, low: u64, high: u64| {
            let text = values.get(key).copied();
            let value = match text {
                Some(text) if !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) => {
                    text.parse::<u64>().map_err(|_| "invalid preview integer")?
                }
                Some(_) => return Err("invalid preview integer"),
                None => default,
            };
            if !(low..=high).contains(&value) {
                return Err("preview bound exceeded");
            }
            Ok(value)
        };
        let total = number(
            "--preview-max-output-bytes",
            128 * 1024 * 1024,
            64 * 1024,
            1024 * 1024 * 1024,
        )?;
        let max_fragment_bytes = number(
            "--preview-max-fragment-bytes",
            4 * 1024 * 1024,
            1024,
            8 * 1024 * 1024,
        )? as usize;
        let limits = PreviewLimits {
            max_clients: number("--preview-max-clients", 4, 1, 16)? as usize,
            max_subscriptions: MAX_SUBSCRIPTIONS,
            max_fragments: 8,
            max_ring_bytes: number(
                "--preview-max-bytes",
                16 * 1024 * 1024,
                64 * 1024,
                64 * 1024 * 1024,
            )? as usize,
            max_fragment_bytes,
            max_initialization_bytes: max_fragment_bytes.min(256 * 1024),
            max_fragment_age_ns: number("--preview-max-age-ms", 30_000, 100, 60_000)? * 1_000_000,
            max_client_bytes: total.min(64 * 1024 * 1024),
            max_total_bytes: total,
        };
        limits
            .validate()
            .map_err(|_| "inconsistent preview memory or traffic bounds")?;
        Ok(Some(Self {
            port: number("--preview-port", 0, 0, 65535)? as u16,
            limits,
        }))
    }

    pub(crate) fn numbers(&self) -> Vec<(&'static str, u64)> {
        let l = &self.limits;
        vec![
            ("preview_port", u64::from(self.port)),
            ("preview_max_clients", l.max_clients as u64),
            ("preview_max_connections", MAX_SUBSCRIPTIONS),
            ("preview_max_subscriptions", l.max_subscriptions),
            ("preview_max_fragments", l.max_fragments as u64),
            ("preview_max_ring_bytes", l.max_ring_bytes as u64),
            ("preview_max_fragment_bytes", l.max_fragment_bytes as u64),
            (
                "preview_max_initialization_bytes",
                l.max_initialization_bytes as u64,
            ),
            ("preview_max_age_ns", l.max_fragment_age_ns),
            ("preview_max_client_bytes", l.max_client_bytes),
            ("preview_max_output_bytes", l.max_total_bytes),
            ("preview_max_header_bytes", MAX_HEADER_BYTES as u64),
            ("preview_io_bytes_per_client_per_step", IO_BYTES as u64),
            ("preview_client_lease_ns", CLIENT_LEASE_NS),
            ("preview_token_bytes", 16),
            ("preview_max_headers", 64),
            ("preview_max_accepts_per_step", 2),
            ("preview_max_response_bytes", 16 * 1024),
        ]
    }

    pub(crate) fn memory_budget(&self) -> u64 {
        (self.limits.max_ring_bytes
            + self.limits.max_fragment_bytes
            + self.limits.max_initialization_bytes
            + self.limits.max_clients * (MAX_HEADER_BYTES + IO_BYTES)) as u64
            + 16
    }

    pub(crate) fn network_budget(&self) -> u64 {
        self.limits.max_total_bytes + MAX_SUBSCRIPTIONS * MAX_HEADER_BYTES as u64
    }

    pub(crate) fn report(&self) -> String {
        object(&[
            ("policy", string(POLICY)),
            ("bind", string("127.0.0.1")),
            ("port", self.port.to_string()),
            ("privacy", string("explicit-local-unredacted")),
            ("delivery", string("independent-durable-window")),
            ("token_delivery", string("operator-stderr-url-fragment")),
            ("recording_backpressure", "false".into()),
            ("transcode", "false".into()),
        ])
    }
}
