# Juniper House Observatory

The observatory is a standalone Next.js showcase for Franken Surveillance. One fictional property has three virtual cameras and three encounters. Visitors can orbit the house, switch cameras, scrub each encounter, and compare camera recordings against the native Rust analysis. The archive includes all nine camera and encounter combinations.

**3D overview and camera views** use Three.js. Scene labels come from the fixture. Visibility tests trace a ray from the virtual camera to the subject center through the property geometry. The fixed camera films are sampled at 12 frames per second.

**FSS replay** opens the selected camera’s film and the matching `fss-event watch` report. FFmpeg takes film frames 0, 3, 6 and so on to make a 160 × 90 MJPEG input at 4 fps. The replay clock seeks to those same frames before drawing the measured boxes. Green boxes show foreground tracks. Blue boxes show associated model detections on their exact inference frames. Select a YOLOX row to inspect that classification. The Rust foreground tracker watches the full image and the pinned YOLOX-Nano package can run on up to two selected frames per film.

**Compare cameras** synchronizes two views of the encounter. `fss-event corroborate` projects each measured track’s foot onto the property ground plane using the virtual camera’s own projection. It evaluates entries into the scenario’s ground zone within 1 metre and 250 milliseconds, including capture-time uncertainty. Selecting an entry seeks both recordings and highlights the measured box in the camera that produced it. Each pair report declares one shared replay source and clock.

On these fixtures the delivery is classified as a person on both the porch and driveway cameras. The porch camera also produces person classifications during the after-hours visit. The raccoon produces zero confirmed image-zone tracks across the three views. All nine pair reports return zero paired candidates. These are results for the included recordings. The scene script supplies the courier role and animal identity.

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
bun run build
```

The build checks each film, native input and report against its indexed SHA-256 digest, verifies the camera projections, and checks that both imports in every pair match the individual camera reports. The output in `out/` is a static site. No device connection, backend credential, or camera permission is required by the browser. Each case has a [camera film](public/films), a [native input and report](public/evidence), and a committed [scenario and camera definition](lib/scenarios.js).

## Verify and deploy

Serve `out/` with a static HTTP server and pass its URL to the browser check.

```sh
node scripts/check-site.mjs http://127.0.0.1:8000
bunx wrangler deploy --dry-run
bun run deploy
```

The [Wrangler configuration](wrangler.jsonc) serves only the static export and binds the custom domain `franken-surveillance.com`. Deployment requires a Cloudflare login with Workers Scripts write access in the owning account and zone access for the custom domain. Keep credentials in the deployment environment.
