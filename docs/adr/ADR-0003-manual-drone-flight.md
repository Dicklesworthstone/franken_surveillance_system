# ADR-0003 — Drone capture is human-piloted; FSS has no flight-control authority

**Status:** Accepted for architecture bootstrap

## Decision

FSS may guide a calibration capture mission and ingest authorized drone video/telemetry, but it
will not autonomously launch, navigate, pursue, or control a drone in this project.

## Rationale

Capture/registration is useful without taking on collision avoidance, airspace, geofencing,
physical safety, vendor SDK support, or adversarial pursuit. The DJI Flip support surface is also
not assumed.

## Consequences

The MCP/CLI capability registry contains no drone flight effect. Any future autonomous robotics
work requires a separate safety case and project boundary.
