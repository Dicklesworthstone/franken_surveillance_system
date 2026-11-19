# Juniper House Observatory

The observatory is a standalone Next.js showcase for Franken Surveillance. One fictional property has three virtual cameras and three encounters. Visitors can orbit the house, switch cameras, scrub each encounter, and compare the animated subject with the results of a native Rust analysis.

**3D overview and camera views** use Three.js. Scene labels come from the fixture. Visibility tests trace a ray from the virtual camera to the subject center through the property geometry. The fixed camera films are sampled at 12 frames per second.

**FSS replay** plays the original camera film with the track boxes reported by `fss-event watch`. The native input is a 160 × 90 MJPEG derivative sampled at 4 frames per second. The full-image zone used in the native runs is independent of the illustrative ground zones in the 3D view. The model stage runs the checked-in YOLOX-Nano package on at most two selected frames per film. Each report preserves unclassified events, skipped inferences, unmatched detections, and the original evidence digests. The reported times are relative to the start of each film.

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

The output in `out/` is a static site. No device connection, backend credential, or camera permission is required by the browser. Each case has a [camera film](public/films), a [native input and report](public/evidence), and a committed [scenario and camera definition](lib/scenarios.js).

## Verify and deploy

Serve `out/` with a static HTTP server and pass its URL to the browser check.

```sh
node scripts/check-site.mjs http://127.0.0.1:8000
bunx wrangler deploy --dry-run
bun run deploy
```

The [Wrangler configuration](wrangler.jsonc) serves only the static export and binds the custom domain `franken-surveillance.com`. Deployment requires a Cloudflare login with Workers Scripts write access in the owning account and zone access for the custom domain. Keep credentials in the deployment environment.
