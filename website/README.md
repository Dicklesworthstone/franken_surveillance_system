# Juniper House Observatory

The observatory is a standalone Next.js showcase for Franken Surveillance. One fictional property has three virtual cameras and three encounters. Visitors can orbit the house, switch cameras, scrub each encounter, and compare camera recordings against the native Rust analysis. The archive includes all nine camera and encounter combinations.

**3D overview and camera views** use Three.js. Scene labels come from the fixture. Visibility tests trace a ray from the virtual camera to the subject center through the property geometry. The fixed camera films are sampled at 12 frames per second.

## The stereo bench

Mark a basketball in the two courtyard films and orbit their lines of sight. Removing either mark leaves depth unresolved. The browser shows the maximum reprojection error through its four-pixel agreement test. The three reference instants each have a native `fss-scene-fuse` report, an exact camera rig, source PNGs extracted from the existing camera films, two authored center marks and a floor-only twin. Each native estimate is conditional on those correspondences. [Open the stereo bench](https://franken-surveillance.com/exhibits/stereo-bench/) · [Source material](public/stereo)

## The courtyard pass

Open **The bounce pass** from the homepage. Change the passer’s height, the player spacing, the release speed, and the floor restitution. Seek to release, first bounce, or the receiver. Both rigged bodies use inverse kinematics to follow the ball. The model applies gravity, horizontal drag, and repeated floor contact. At the receiver’s plane a ball between 0.57 and 1.56 metres is catchable. With the reference settings it arrives at 0.89 m. The soft-bounce preset changes only the restitution and sends it past at 0.14 m.

The studio, garden, and patio films each contain 96 frames over four seconds. The two fixed views were imported into Rust at 4 fps. At one second an explicit YOLOX-Nano inspection returned two people in each camera. The motion-triggered watch skipped that frame. Select a different watch sample, open its exact JPEG and content-addressed report, or locate it in the 3D view. The measurement overlays apply to the recorded settings. A separately archived earlier take preserves a bicycle proposal over one player’s legs in a scene with no bicycle. [Reference material](public/court) · [Model and environment credits](art/README.md)

## The parcel drop

Open **Motion lab** to follow an articulated courier across the front path. Adjust stature, walking speed, release height and restitution. Studio joint trails show three sample times during the approach. Switch to the property orbit or the synchronized porch and driveway projections, then seek directly to release, first contact or rest. The gait uses two-link inverse kinematics and planted feet. The parcel uses vertical free fall and restitution on level ground. A live side-elevation diagram supports browsers without WebGL.

The three reference films each contain 216 frames over nine seconds. The two fixed cameras were imported into FSS at 4 fps. The evidence cards show the original 160 × 90 JPEGs from those imports at one second, with the detector’s measured bounds. Both reference views returned the class `person` at that instant. Custom parameter combinations show the simulated camera views and can be reset to inspect the measured reference. [Reference films and native reports](public/motion)

**FSS replay** opens the selected camera’s film and the matching `fss-event watch` report. FFmpeg takes film frames 0, 3, 6 and so on to make a 160 × 90 MJPEG input at 4 fps. The replay clock seeks to those same frames before drawing the measured boxes. Green boxes show foreground tracks. Blue boxes show associated model detections on their exact inference frames. Select a YOLOX row to inspect that classification. The Rust foreground tracker watches the full image and the pinned YOLOX-Nano package can run on up to two selected frames per film.

**Compare cameras** synchronizes two views of the encounter. `fss-event corroborate` projects each measured track’s foot onto the property ground plane using the virtual camera’s own projection. It evaluates entries into the scenario’s ground zone within 1 metre and 250 milliseconds, including capture-time uncertainty. Selecting an entry seeks both recordings and highlights the measured box in the camera that produced it. Each pair report declares one shared replay source and clock.

On these fixtures the delivery is classified as a person on both the porch and driveway cameras. The porch camera also produces person classifications during the after-hours visit. The raccoon produces zero confirmed image-zone tracks across the three views. At the original 250 ms gate all nine pair reports return zero paired candidates. These are results for the included recordings. The scene script supplies the courier role and animal identity.

## Follow the doorstep event

Survey mode draws measured porch and driveway entries on the same Three.js property model as the camera replays. Select a timeline row to inspect its ground position and source time.

The evidence desk replays the delivery through the native association engine twice. The two candidate entries are 29 cm apart with a 252 ms worst-case separation. A separate, explicit 500 ms time window admits one witnessed entry. The shared scene and clock leave the alert policy on hold. The featured split-screen film and camera stills use those actual entry frames.

The ledger exhibit publishes the event in an isolated local deployment, retries the same approval, and audits the committed revision with `fss-custody`. The browser can rehash the two exported objects or change a byte in a temporary copy. In the agent console, visitors can read the original `fss/1` responses for orientation, forensic explanation, refused alert planning, handoff, and resume. Lighting, gate, and siren adapters are design examples. The belief lab separately runs `fss-fuse` with an illustrative prior and likelihood bounds under three source-dependence assumptions. Each exhibit links its full native outputs. Re-running the example creates a new session-journal observation and handoff receipt. The retained event objects and original camera evidence remain content-addressed.

The homepage film selector opens the courtyard, parcel drop and night garden. Its covers and films come from the included scenes. [Artwork sources](art/README.md)

## Run locally

From this directory, use Bun and a Node.js release supported by Next.js 16.

```sh
bun install --frozen-lockfile
bun run dev
```

## Rebuild the films and native evidence

The committed media and reports are ready to serve. To regenerate them, build `fss-file`, `fss-event`, `fss-infer`, and `fss-scene-fuse` with the repository's pinned Rust toolchain. Set `FSS_BIN_DIR` if those executables live outside the default `target/debug` directory. The media renderer uses Chromium, Playwright, and FFmpeg on the development host. Set `CHROME_BIN` if Chromium is installed somewhere other than `/usr/bin/google-chrome`.

```sh
bun run films
python3 scripts/native-evidence.py
python3 scripts/field_case.py
node scripts/render-films.mjs --motion
python3 -B scripts/motion-evidence.py
node scripts/render-films.mjs --court
python3 -B scripts/motion-evidence.py --scene court
node scripts/render-films.mjs --stereo
python3 -B scripts/stereo-evidence.py
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

## Camera wall and section sharing

The camera wall combines a moving WebGL flyover with the three existing camera films. Each 12-second reel has 144 frames on a shared clock. Pause, step by a frame, or jump to the first native inference. The readout links to the per-camera report and distinguishes measured classes, skipped inferences and frames between native samples. The overhead button in the simulator shows the same property from above.

From this directory, regenerate the wall reels and roof plan with the existing camera films in place.

```sh
node scripts/render-films.mjs --wall
```

Use an exhibit link to open its standalone page. The home page and fourteen exhibit pages export distinct 1200 × 630 Open Graph cards and 1200 × 600 X cards. Next.js renders them locally with ImageResponse, using the site artwork, WebGL stills, camera frames and native fixture outputs. Each PNG URL includes a digest of its bytes. The browser verification fetches both images for every page with JavaScript disabled.

The poster room provides all thirty full-size PNGs as direct downloads. [Open the poster room](https://franken-surveillance.com/exhibits/poster-room/)

The [ranked demo ideas](DEMO_IDEAS.md) include the three additions implemented here and the ranked courtyard series.
