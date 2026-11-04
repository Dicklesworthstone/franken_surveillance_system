# Question of Record — RS-20261104-cameraroot

**Question:** Why has no camera in the fleet been actually rooted-and-held or firmware-replaced, despite (a) a C460 exploit that has spawned root shells 3× today, (b) a C660 offline ROP chain, and (c) a Wyze MITM with 333 camera requests through it?

**Falsifier:** If, on inspection, the captured shell/port-4444 events were artifacts of probe-and-consume sequencing (i.e., we never read a single byte from a root shell, never executed a single command), and the Wyze payloads are unfetchable by the cameras due to a schema/URL/signature defect we control, then the "rooted/armed" narrative is false and the blocking set is the payload/schema defects themselves — not camera sleep cycles.

**Scope:** The three blocking mysteries: (M1) C660 shell binds but carries no commands — why; (M2) C460 root is 3×-proven but never converted — what does conversion actually require; (M3) Wyze cameras poll get_processes/download_location but never fetch our payloads — what breaks the fetch.
**Out of scope:** Owlet (vendor DTLS bug), Yi (operator gate), any hardware modification.
