#![forbid(unsafe_code)]
//! HEVC and JPEG wire owners use the same original-datagram custody format as AVC.
//! Control messages (including opaque bodies and authentication) are never admitted.

use super::*;
use crate::rtsp::RtspEvent;
use crate::rtsp::framed::RtspWireFrame;

impl DatagramArchive {
    /// Prepare an actual parsed interleaved frame, without its four-byte envelope.
    ///
    /// This borrows the original frame emitted by a native framed protocol owner.
    /// Requests, responses and authentication challenges are refused BEFORE work or
    /// allocation, even if their bodies look like RTP. No raw-wire payload sniffing
    /// or reparsing can accidentally archive credentials. The exact channel, parser
    /// receive timestamp and opaque original datagram use the unchanged custody
    /// format, bounds, chain and publication barriers shared with AVC.
    pub fn prepare_frame<'a>(
        &self,
        frame: &'a RtspWireFrame,
        budget: &mut WorkBudget<'_>,
    ) -> Result<PreparedDatagram<'a>> {
        let RtspEvent::Interleaved { channel, span } = frame.event() else {
            return Err(DatagramArchiveError::Source);
        };
        self.prepare_bytes(*channel, frame.received_ns(), span, budget)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtsp::framed::RtspWireIntake;
    use crate::rtsp::tcp::TcpSecurityPolicy;
    use fss_object::SpoolLimits;
    use fss_packet::StreamKey;
    use fss_publication::{LocalPublicationLimits, NeverCancel};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    type Test<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Test<Self> {
            for _ in 0..256 {
                let path = std::env::temp_dir().join(format!(
                    "fss-framed-custody-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                ));
                match std::fs::create_dir(&path) {
                    Ok(()) => return Ok(Self(path)),
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(e) => return Err(e.into()),
                }
            }
            Err("fixture directory bound".into())
        }
        fn open(&self) -> Test<LocalRootPublisher> {
            Ok(LocalRootPublisher::open(
                &self.0,
                LocalPublicationLimits::new(
                    16,
                    8,
                    16,
                    64,
                    SpoolLimits::new(64, 1024 * 1024, 65_536, 64),
                ),
            )?)
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn archive() -> Test<DatagramArchive> {
        Ok(DatagramArchive::new(
            DatagramScope {
                binding: TcpBinding::new(
                    StreamKey {
                        ingress: 92,
                        generation: 1,
                        ssrc: 7,
                    },
                    "127.0.0.1:554".parse()?,
                    "camera.local",
                    TcpSecurityPolicy::OwnerApprovedPlaintext,
                )?,
                channels: (0, 1),
                receive_clock: ContentDigest::sha256(b"original frame clock"),
                retention_evidence: ContentDigest::sha256(b"explicit RTP and RTCP retention"),
            },
            DatagramArchiveLimits {
                max_datagrams: 16,
                max_payload_bytes: 1024 * 1024,
                max_scan_roots: 64,
                max_spool_object_bytes: 65_536,
            },
        )?)
    }
    fn frame(bytes: &[u8], time: u64) -> Test<RtspWireFrame> {
        let mut intake = RtspWireIntake::new();
        // Force fragmented framing; the recorded timestamp comes from completion.
        for (i, byte) in bytes.iter().enumerate() {
            intake.ingest(&[*byte], if i + 1 == bytes.len() { time } else { 0 })?;
            if i + 1 != bytes.len() {
                assert!(intake.poll(0)?.is_none());
            }
        }
        intake
            .poll(time)?
            .ok_or_else(|| "frame did not complete".into())
    }
    fn media(channel: u8, payload: &[u8], time: u64) -> Test<RtspWireFrame> {
        let mut wire = vec![b'$', channel];
        wire.extend_from_slice(&u16::try_from(payload.len())?.to_be_bytes());
        wire.extend_from_slice(payload);
        frame(&wire, time)
    }
    fn work() -> WorkBudget<'static> {
        WorkBudget::new(100_000_000)
    }

    #[test]
    fn framed_datagrams_survive_cold_reopen_before_any_picture_exists() -> Test {
        let dir = Directory::new()?;
        // An incomplete HEVC fragment, a duplicate and malformed/empty RTCP are
        // still exact source observations; none is a recording or invented EOF.
        let observations: &[(u8, &[u8])] = &[
            (
                0,
                &[0x80, 96, 0, 1, 0, 0, 0, 0, 0, 0, 0, 7, 98, 1, 0x81, 0xaa],
            ),
            (
                0,
                &[0x80, 96, 0, 1, 0, 0, 0, 0, 0, 0, 0, 7, 98, 1, 0x81, 0xaa],
            ),
            (1, b"malformed RTCP"),
            (1, b""),
        ];
        let (pin, scope, limits) = {
            let mut p = dir.open()?;
            let mut a = archive()?;
            for &(channel, payload) in observations {
                let frame = media(channel, payload, 17)?;
                let plan = a.prepare_frame(&frame, &mut work())?;
                let receipt = a.publish(&plan, &mut p, &NeverCancel, &mut work())?;
                assert_eq!(receipt.record.payload_bytes, payload.len());
                assert_eq!(receipt.record.received_ns, 17);
                assert_eq!(receipt.local.claims.local, LocalPublicationState::Durable);
            }
            (a.pin(), a.scope.clone(), a.limits)
        };
        let p = dir.open()?;
        let a = DatagramArchive::recover(&p, scope, limits, Some(pin), &NeverCancel, &mut work())?;
        for (i, &(channel, bytes)) in observations.iter().enumerate() {
            let source = a.read(i as u64 + 1, &p, &NeverCancel, &mut work())?;
            assert_eq!(source.payload(), bytes);
            assert_eq!(
                (source.record().channel, source.record().received_ns),
                (channel, 17)
            );
        }
        assert_eq!(a.pin().datagrams, 4);
        Ok(())
    }

    #[test]
    fn control_and_digest_wire_never_enter_source_storage_or_spend_work() -> Test {
        let a = archive()?;
        let before = a.pin();
        for wire in [
            "RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Length: 4\r\n\r\n$\0\0\0",
            "RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\nWWW-Authenticate: Digest realm=\"fixture\", nonce=\"test-only\"\r\nContent-Length: 0\r\n\r\n",
            "OPTIONS rtsp://camera.local/live RTSP/1.0\r\nCSeq: 1\r\nContent-Length: 0\r\n\r\n",
        ] {
            let frame = frame(wire.as_bytes(), 3)?;
            let mut budget = work();
            assert!(matches!(
                a.prepare_frame(&frame, &mut budget),
                Err(DatagramArchiveError::Source)
            ));
            assert_eq!(budget.used(), 0);
            assert_eq!(a.pin(), before);
        }
        Ok(())
    }

    #[test]
    fn framed_input_keeps_channel_time_work_and_count_limits() -> Test {
        let mut a = archive()?;
        let good = media(0, b"opaque", 8)?;
        let wrong = media(2, b"opaque", 8)?;
        assert!(matches!(
            a.prepare_frame(&wrong, &mut work()),
            Err(DatagramArchiveError::Source)
        ));
        assert!(matches!(
            a.prepare_frame(&good, &mut WorkBudget::new(0)),
            Err(DatagramArchiveError::Work(_))
        ));
        let dir = Directory::new()?;
        let mut p = dir.open()?;
        let plan = a.prepare_frame(&good, &mut work())?;
        a.publish(&plan, &mut p, &NeverCancel, &mut work())?;
        let earlier = media(0, b"earlier", 7)?;
        assert!(a.prepare_frame(&earlier, &mut work()).is_err());
        a.limits.max_datagrams = 1;
        assert!(a.prepare_frame(&good, &mut work()).is_err());
        assert_eq!(a.pin().datagrams, 1);
        Ok(())
    }
}
