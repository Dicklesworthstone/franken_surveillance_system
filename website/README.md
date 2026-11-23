# Franken Surveillance website

One page at [franken-surveillance.com](https://franken-surveillance.com/). It plays a staged one-minute intrusion at a fictional house as five camera films on one clock, beside a model of the site with the tracked people, a chart of which camera saw whom, the agent's calls and the ledger rows. Five chapters explain each capability and state what runs today, what is built but unproven and what is planned.

Figures carry one of four marks that say where their contents come from. Staged figures come from the scene script. Measured figures are output of the repository's own binaries run over the five film files. Browser figures are computed on the page from the scene's camera geometry. Design figures list what the project's registries and plan define, or are our own comparison and say so.

## Layout

| Path | Holds |
|---|---|
| `app/page.jsx`, `app/layout.jsx`, `app/styles/` | The route, its metadata and its styles. |
| `components/site/` | The page. `chapters.js` names the chapters and their sections; `ui.jsx` holds the shared parts (headings, chapters, sections, framed figures, provenance badges). |
| `lib/watch/` | Reading the take, the geometry, the staged account and the reducer for measured output. See its README. |
| `public/watch/intrusion/` | The films, `scene.json`, site backdrops, hero loop, stills and credits. |
| `art/estate/` | The Blender source for the house, the people and the films. See its README. |
| `scripts/watch-evidence.py` | Runs the FSS binaries over the films and writes `native.json` and `native-boxes.json`. |
| `scripts/check-site.mjs` | Browser check of a running copy of the site. |
| `scripts/make-plates.mjs` | Resizes renders already in the repository into `public/watch/plates/`. It uses the copy of `sharp` that Next.js installs. |
| `scripts/make-share-cards.mjs` | Draws `app/opengraph-image.jpg` and `app/twitter-image.jpg` in the page's own type and colours. |
| `scripts/test-hero-truth.mjs` | Checks the staged outline over the hero loop against the scene file and the loop's lens. Run it with `node --test`. |

## Design

The page is dark throughout, because night footage is only readable against a dark surround. `app/styles/tokens.css` explains the roles: `ink` is the ground, `lamp` is for actions and the one lit phrase in a heading, and each chapter wears one kind of light a night camera has to deal with (sodium, moonlight, infrared, phosphor, dawn). Chapter colours are for numerals, eyebrows and frames. Data colours (`--track-a`, `--track-b`, `--seen`) mean the same thing everywhere and are used for nothing else.

Five films can play at once, so the page adds nothing over them that the browser would have to work out again per frame: no grain layer, no mask on a playing video, no rounded clip round the console, and no blur behind the readout over the hero loop. Over a console film there are only its outlines and their labels. The header and the phone dock are blurred glass and do pass over the films while the page scrolls.

Type is Inter with its optical sizes and JetBrains Mono, both self-hosted from Fontsource through `next/font/local`.

## Build and check

Run from this directory with Bun, Node.js and FFmpeg's `ffprobe` on PATH. The static export checks each imported camera film’s stream, frame count and duration against its displayed measurements.

```sh
bun install --frozen-lockfile
bun run build
bun run preview
bun run check:site http://127.0.0.1:8000
```

`bun run build` exports static HTML to `out/` and keeps only `public/watch` from the public folder. The check loads the page at four widths, plays and scrubs the five films, uses each interactive figure and confirms that retired addresses return 404. Set `CHROME_BIN` if Google Chrome is not at `/usr/bin/google-chrome`.

The delivery replay at `/#delivery-dropout` plays a complete porch recording beside a copy missing two seconds. Both use the night film’s fictional house. Pick the last frame before the gap or the first frame after it to inspect where the native reader can place a picture. The receipts below the player link to both recordings, their presentation times and the intervals covered by a watch. Run `node scripts/check-delivery-dropout-browser.mjs http://127.0.0.1:8000` to exercise the controls and media recovery.

## Regenerate the films and the measured output

The films are path-traced in Blender from a frozen copy of the estate, with scanned people driven by motion capture. The steps and the asset licences are in `art/estate/README.md`, under Films. `camera_looks.py` grades and encodes each camera and writes `scene.json`.

After the films change, run the project's binaries over them. `FSS_BIN_DIR` is the directory holding the release binaries.

```sh
FSS_BIN_DIR=/path/to/target/release python3 -B scripts/watch-evidence.py public/watch/intrusion
```

The script imports the film bytes into a private deployment and runs custody, motion watch, detection, tracking, two-camera corroboration and fusion. For a corroborated event it exercises the alert workflow against its own loopback relay. New recordings count relay requests separately for dispatch and retry. The original take retained one aggregate request count. The page shows refusals and missing observations alongside successful results.

The original `native.json` includes an author’s note that understates coverage. Each retained watch report states whether its pipeline recorded an interval without a confirmed foreground-track entry into the watched zone. The page reads those reports directly. A gap between witnesses can contain a recorded entry.

## Reproduce the edited two-camera fusion excerpt

From the repository root, run the following with the release binaries and FFmpeg installed. The work directory must be new.

```sh
python3 scripts/check_residential_class_fusion.py --bins target/release --work /tmp/fss-residential-replay
cmp /tmp/fss-residential-replay/fusion-replay.json website/public/watch/intrusion/fusion-replay.json
diff -qr /tmp/fss-residential-replay/fusion-replay website/public/watch/intrusion/fusion-replay
```

The replay holds frame 240 seven times and then uses frames 343 through 347 from both films. The script checks the model scores, the held-out calibration bins, the common-cause group and the result of removing the group. If you publish a new qualified excerpt, update its digest in `lib/watch/fusion-excerpt.mjs` together with both generated files.

## Reproduce the notification comparison

From the repository root, run the same camera excerpt through a private loopback HTTP receiver. Choose a new directory for the run.

```sh
python3 -B scripts/check_residential_relay.py --bins /path/to/target/release --work /tmp/fss-relay-example
```

The receiver counts every POST and retains its body. One branch returns HTTP 200. A second reads the same request and closes the connection before acknowledging it. Inspect `relay-replay.json` in the run directory for the native outcome of each approval, retry and inspection. The held event exercises the earlier policy decision. The website displays one pinned run. A fresh run can have different timestamps and a different loopback port.

## Credits

The house is fictional and modelled for this project. The two people are Renderpeople scans published under CC BY 4.0, moved by clips from the CMU motion capture database. `public/watch/intrusion/CREDITS.txt` lists every third-party asset, its licence and what was changed, and ships with the site.

## Deploy

The pinned Cloudflare CLI deploys `out/` as static assets. It reads the custom domain and Worker name from `wrangler.jsonc`.

```sh
bun run deploy
```
