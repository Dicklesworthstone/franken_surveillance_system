# Cold AVC reconstruction from retained original datagrams

`rtsp::datagram_reconstruction::DatagramAvcReplay` connects `DatagramArchive`
to the existing pure-Rust `AvcReceiver`. It reads and re-verifies original RTP/RTCP
observations from the caller's current `LocalRootPublisher`, not a second source
cache, camera connection or foreign decoder. The same publisher remains available
between steps for publication of downstream derived recordings.

Supply an independently accepted recovered archive, exact SPS/PPS bytes (without
Annex-B start codes), payload number, packetization mode, RTCP mode, every receiver
limit and configuration evidence. Missing configuration is not reconstructed from
defaults or an unrelated latest SDP. A digest binds the complete source prefix,
parameter bytes, configuration evidence, limits and scheduler policy. It is an
interpretation identity, not authentication, original-live-schedule equivalence,
camera timing calibration or permission to disclose source.

## Three clocks remain different

The replayer uses recorded parser-completion receive times as a virtual scheduling
clock. It drains immediately available native receiver output between observations.
A receiver wake strictly before the next recorded arrival advances virtual time
without reading that arrival. A future tie chooses arrival admission; the native
receiver's own deadline rules still apply inside that admission. Current storage
admission time and its absolute lease are independent. Neither becomes picture
DTS, duration, composition time or physical camera capture time.

This deliberately defines a reproducible new interpretation; it does not claim to
reconstruct the original live CPU/poll schedule. Source identity and interpretation
identity remain distinct. Every original observation is returned, including RTP
probation, duplicate sequence numbers, identical retransmissions and invalid RTCP.
Malformed RTP returns `InputRefused` with the exact source and receiver retirement.
Confirmed stream restart closes the old-epoch attempt instead of changing epochs.

## A durable prefix is not EOF

At the last retained arrival the receiver's immediately available output drains,
then the result is `PrefixExhausted`. The driver never calls `finish()` and never
advances a timer beyond that last arrival merely to empty a queue. Remaining packet,
fragment and picture accounting is returned explicitly. A prefix ending halfway
through FU-A therefore cannot become an invented complete picture or recording.
An actual in-band codec termination is `CodecEnded`, with unconsumed source count
and the original terminal event; it is not a claim that the TCP stream ended.

Each step performs at most one original read/admission or one receiver poll result
or timer advance. The source store's own read may perform multiple bounded storage
calls. Runtime ceilings cover complete source bytes, total calls, current deadline,
source-read work and a conservative worst-case receiver traversal/copy reservation.
Those units are admission bounds, not calibrated CPU/performance measurements.
No automatic retry or silent truncation occurs when a bound is exhausted.

Pass the live storage-authority/cancellation probe and cooperative work budget at
every step. Source corruption, deletion, uncertain custody or cancellation fences
the attempt. A post-computation refusal returns the withheld original/media result
along with receiver retirement. Clock regression is a safe unchanged-state refusal.
No cleanup path deletes retained evidence, contacts a camera or flushes codec EOF.
The source store still requires protected ownership and independently trusted pins
when whole-store rollback is in the threat model.

## Validation and limits

Thirteen authored integration tests use real encoded AVC, the existing Digest/RTSP
parser to obtain opaque source observations, and the actual filesystem publisher.
They cover cold native-receiver comparison, independent clocks and configuration,
truncated fragments, duplicates, invalid RTCP, malformed RTP, timer scheduling,
post-read cancellation, corruption, budgets, deadlines and empty prefixes.

```sh
cargo test -p fss-reference --test datagram_avc_reconstruction
```

Rust compilation, tests, rustfmt and Clippy were not run in this editing environment
because cargo/rustc are unavailable. Static checks are not compiled-Rust evidence.
This is not full raw-TCP preservation, a hardware decoder, a restored live session,
a production throughput claim, or a qualification/gate closure.
