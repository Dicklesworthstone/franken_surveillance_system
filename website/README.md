# Juniper House Observatory

The observatory is a standalone Next.js showcase for Franken Surveillance. One fictional property has three virtual cameras and three encounters. Visitors can orbit the house, switch cameras, scrub each encounter, and compare camera recordings against the native Rust analysis. The archive includes all nine camera and encounter combinations.

**3D overview and camera views** use Three.js. Scene labels come from the fixture. Visibility tests trace a ray from the virtual camera to the subject center through the property geometry. The fixed camera films are sampled at 12 frames per second.

**FSS replay** opens the selected camera’s film and the matching `fss-event watch` report. FFmpeg takes film frames 0, 3, 6 and so on to make a 160 × 90 MJPEG input at 4 fps. The replay clock seeks to those same frames before drawing the measured boxes. Green boxes show foreground tracks. Blue boxes show associated model detections on their exact inference frames. Select a YOLOX row to inspect that classification. The Rust foreground tracker watches the full image and the pinned YOLOX-Nano package can run on up to two selected frames per film.

**Compare cameras** synchronizes two views of the encounter. `fss-event corroborate` projects each measured track’s foot onto the property ground plane using the virtual camera’s own projection. It evaluates entries into the scenario’s ground zone within 1 metre and 250 milliseconds, including capture-time uncertainty. Selecting an entry seeks both recordings and highlights the measured box in the camera that produced it. Each pair report declares one shared replay source and clock.

On these fixtures the delivery is classified as a person on both the porch and driveway cameras. The porch camera also produces person classifications during the after-hours visit. The raccoon produces zero confirmed image-zone tracks across the three views. At the original 250 ms gate all nine pair reports return zero paired candidates. These are results for the included recordings. The scene script supplies the courier role and animal identity.

## Follow the doorstep event

Survey mode draws measured porch and driveway entries on the same Three.js property model as the camera replays. Select a timeline row to inspect its ground position and source time.

The evidence desk replays the delivery through the native association engine twice. The two candidate entries are 29 cm apart with a 252 ms worst-case separation. A separate, explicit 500 ms time window admits one witnessed entry. The shared scene and clock leave the alert policy on hold. The featured split-screen film and camera stills use those actual entry frames.

The ledger exhibit publishes the event in an isolated local deployment, retries the same approval, and audits the committed revision with `fss-custody`. The browser can rehash the two exported objects or change a byte in a temporary copy. In the agent console, visitors can read the original `fss/1` responses for orientation, forensic explanation, refused alert planning, handoff, and resume. Lighting, gate, and siren adapters are design examples. The belief lab separately runs `fss-fuse` with an illustrative prior and likelihood bounds under three source-dependence assumptions. Each exhibit links its full native outputs. Re-running the example creates a new session-journal observation and handoff receipt. The retained event objects and original camera evidence remain content-addressed.

The opening scene is artwork generated with the built-in ImageGen tool. The brief was a blue-hour Craftsman house, warm porch and garage lights, dark trees on the left, and subtle teal survey lines at the right edge. The interactive twin and both sets of films use the repository’s Three.js model.

## Run locally

From this directory, use Bun and a Node.js release supported by Next.js 16.

```sh
bun install --frozen-lockfile
bun run dev
```

## Rebuild the films and native evidence

The committed media and reports are ready to serve. To regenerate them, build `fss-file` and `fss-event` with the repository's pinned Rust toolchain. Set `FSS_BIN_DIR` if those executables live outside the default `target/debug` directory. The media renderer uses Chromium, Playwright, and FFmpeg on the development host. Set `CHROME_BIN` if Chromium is installed somewhere other than `/usr/bin/google-chrome`.

```sh
bun run films
python3 scripts/native-evidence.py
python3 scripts/field_case.py
bun run build
```

The field case uses the same binary directory for `fss`, `fss-event`, `fss-file`, `fss-fuse`, and `fss-custody`. Its FFmpeg captions use the DejaVu Sans Mono font from the Linux `fonts-dejavu-core` package.

The build checks each film, native input and report against its indexed SHA-256 digest, verifies the camera projections, and checks that both imports in every pair match the individual camera reports. The output in `out/` is a static site. No device connection, backend credential, or camera permission is required by the browser. Each case has a [camera film](public/films), a [native input and report](public/evidence), and a committed [scenario and camera definition](lib/scenarios.js).

## Verify and deploy

Serve `out/` with a static HTTP server and pass its URL to the browser check.

```sh
node scripts/check-site.mjs http://127.0.0.1:8000
bunx wrangler deploy --dry-run
bun run deploy
```

The [Wrangler configuration](wrangler.jsonc) serves only the static export and binds the custom domain `franken-surveillance.com`. Deployment requires a Cloudflare login with Workers Scripts write access in the owning account and zone access for the custom domain. Keep credentials in the deployment environment.
