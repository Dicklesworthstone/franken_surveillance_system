# Source-attributed discovery and retained network liveness

Discovery can retain an owner-enrolled endpoint's current ICMP/TCP, Tuya beacon,
mDNS, SSDP, or WS-Discovery response. The response kind and actual sender stay
separate from camera-service advertisements. In particular, an mDNS sleep proxy
can advertise another camera's SRV/A address without making that camera live.
Aggregate probe counts, cached ARP entries, OUI/vendor labels, and advertised
URLs never refresh liveness.

Tuya announcements contribute only after their frame integrity verifies: CRC32
and suffix for 55AA, or the broadcast-key GCM tag and suffix for 6699. Failed
frames remain available to the raw diagnostic decoder but cannot create a
candidate or refresh health. The public broadcast key establishes protocol
integrity; owner credentials are still required for device access.

## Candidate discovery and owner enrollment

Run discovery only on an authorized local subnet and interface:

```sh
fss-discover --subnet 192.168.4.0/24 --iface 192.168.4.2 \
  --owner-authorized --json
```

ONVIF WS-Discovery responders and complete camera-specific mDNS SRV/A chains now
produce candidates even without an ARP entry. The report includes
`observed_this_sweep`, typed `response_kinds`, and `advertised_services` with the
actual responder and advertised SRV port. Standards candidates name
`StandardsEndpointCredentials` as the missing owner-approved endpoint and scoped
credentials. An advertisement grants no streaming authority or conformance claim.
Generic HTTP, Matter, HomeKit, and Google Cast advertisements alone do not classify
a device as a camera. Repeated advertisements do not inflate confidence.

All probe results are filtered against the original validated host set. mDNS
records may join across packets from one responder, never across responders.
Zero-TTL PTR, SRV, or A withdrawals suppress the relevant service claim for the
sweep. Escaped dots inside DNS labels cannot impersonate a service boundary.
Unresolved addresses, zero SRV ports, and out-of-scope advertised addresses do
not create onboarding paths. Advertised URLs are neither followed nor logged.
Raw observation bounds and a 1,024-service-hint bound reject report expansion
before returning partial results.

For an already enrolled sensor, add the existing retention options:

```sh
fss-discover --subnet 192.168.4.0/24 --iface 192.168.4.2 \
  --root /srv/fss --site site:home --bind 192.168.4.44=sensor:front,onvif \
  --watch 30 --owner-authorized --json
```

The binding is explicit and must stay inside the configured scope. Existing
enrollment conflict checks and short publication locks still apply. Discovery
neither provisions credentials nor changes the sensor's immutable binding.

`SensorLivenessRecord::protocol_responses()` exposes these typed response kinds.
The response time remains an interval from sweep start through completion, and
silence ages from the earliest possible response. A long sweep cannot timestamp
an early response at its completion. Restart preserves the last unobserved
assessment, even after a later response makes the endpoint observable again.
Network liveness establishes neither authenticated identity nor decoded pixels,
stream continuity, scene coverage, or evidence of absence.

## Durable compatibility

The existing `fss.sensor_liveness_record.v1` format is unchanged byte for byte.
Records with no explicit protocol-response kinds continue to use v1, preserving
old payload digests and exact retries. The v2 domain
`fss.sensor_liveness_record.v2` carries the same fields followed by a nonempty
response-kind list, encoded as a count and canonical strings. Its list is sorted
by the stable string spellings, unique, and limited to the five registered
kinds. Unknown, repeated, unordered, empty-v2, trailing, or oversized encodings
are refused. Histories may contain both domains, linked by exact predecessor
digests in the same authority family.

An exact retry must preserve the sweep window, owner enrollment, TCP ports,
beacon commands, and protocol-response kinds. Changing mDNS evidence to
WS-Discovery evidence for the same sweep is a conflict; it cannot append a
replacement history. Existing generation, chronology, custody, root-last
publication, and enrollment checks still apply.

## Deterministic verification

`discovery_protocol_liveness_contract` covers unchanged v1 bytes and cold reopen,
mDNS-only liveness followed by outage and WS-Discovery recovery, retry conflicts,
sleep-proxy attribution through the composition and retention owners, strict v2
decoding, sweep-time uncertainty, and admission before publication. These tests
use synthetic observations and local retained objects. They do not qualify a
physical device, multicast interface, or live camera stream.

The standards probes still bind their local source address and rely on the OS
multicast route; this work does not qualify interface selection on physical
networks. The reference census retains its existing bounded system ping/ARP
shell and socket implementation. It is not a claim of production runtime or
hardware qualification.
