# The watch page

The home page plays one staged take on a single clock: the camera films, a model of the site with the tracked people, a chart of which camera saw whom, the agent's calls and the ledger rows.

## Files

| File | Purpose |
|---|---|
| `take.js` | Turns a take's `scene.json` into the shape the components use, and derives sightings, per-frame estimates and trails. Runs at build time and in the browser. |
| `geometry.js` | The position bound a set of cameras supports: one camera's information about a ground point, and the ellipse several add up to. |
| `story.js` | The staged account: agent calls, ledger rows, timeline markers and the running assessment, timed from the take's own beats. |
| `evidence.js` | The weights behind the staged assessment. |
| `native.js` | Reduces `native.json` to the figures the measured panels print. |
| `hero.js` | Server side. The staged outline, camera lamps and action for each frame of the hero loop, from `scene.json` projected through the loop's own lens. `scripts/test-hero-truth.mjs` checks it against `take_hero.py`, `takes.py` and the scene file. |
| `load.js` | Server side. Reads the published take at build time. |
| `retained.mjs` | Server side. Reads the tools' retained reports by their SHA-256, checks the summary in `native.json` against them, and computes the digest that ties the rendered page to its inputs. |
| `fusion-excerpt.mjs` | Server side. Reads the edited two-camera fusion replay and refuses it unless it matches the scene file, the films and its own recorded digests. |
| `relay-replay.mjs` | Server side. Reads the alert relay comparison and refuses it unless it matches the fusion replay it was made from and the captured run it is pinned to. |
| `delivery-dropout.mjs` | Server side. Reads the porch recording with two seconds missing and refuses it unless every file matches its recorded digest, the tool's coverage record marks the missing two seconds as uncovered and says it bounded confirmation to continuous decoded frames, and none of its no-entry witnesses reaches into them. |

Components are in `components/site/`, styles in `app/styles/`.

## Data

Everything for the take is in `public/watch/intrusion/`.

`scene.json` (`fss.website.watch.v1`) comes from the film renderer in `art/estate/`. It holds the clock, each camera's calibration, look and film path, the scripted ground track of each person, each person's box in each camera per frame, the scripted effects, and the mapping from plan metres onto each site backdrop. Everything in it is scripted.

`twin/twin.json` lists the site backdrops and their mappings. The loader lays it over the `twin` block in `scene.json`, so a backdrop rendered after the films does not require rewriting the scene file. `front` is the tilted view the console opens on; `plan` looks straight down.

`native.json` (`fss.website.watch_native.v1`) and `native-boxes.json` are the output of the project's own binaries run on the film files by `scripts/watch-evidence.py`, with the tools' own reports beside them in `native/objects/`. The page marks anything from these files as measured. Without them the measured panels are left out.

Two facts are read from the tools' reports directly (`fromReports` in `retained.mjs`), because the published `native.json` was written by an earlier driver that got them wrong: whether absence is certified inside the coverage witnesses, and the ledger's position at the end of the run. The driver has since been corrected and a new run carries both itself.

The tools do not know where the staged people were. `load.js` compares every cross-camera match with the scripted positions, using the tools' own distance gate, and the page says for each match whether it landed on a person. A match on nobody within a second and a half after the floodlights come on is flagged as coinciding with them. The page states the timing and does not claim a cause.

`hero.mp4` is the loop behind the headline and `hero-still.jpg` the frame shown before it plays and when the visitor asks for reduced motion. `plates/` holds a wide cut of `stills/floods.jpg` that the page no longer shows. The pictures behind the chapter openers and the camera thumbnails are in `public/watch/plates/`, resized from renders by `scripts/make-plates.mjs`, with the SHA-256 of each source in `plates.json`. `CREDITS.txt` lists every third-party asset, its licence and what was changed.

A second, separate recording is in `public/watch/delivery-dropout/`: eight seconds from a porch camera at the same fictional house, once complete and once with two seconds removed, with the tools' import, presentation and coverage reports for both. The walk-through step on coverage shows it.

## Sources of each figure

The page uses four marks, each told apart by shape as well as colour. Staged (dashed ring): positions, agent calls, ledger rows and effects, which come from the script, and the readout over the hero loop. Measured (solid dot): output of the FSS binaries. Computed in the browser (square): the position bounds, which are derived from camera geometry while you watch, and the SHA-256 in the byte check. From the design registry (diamond): the knowledge states, agent views and operations, which are the project's own lists and not results.

## Playback

Each film is fetched whole and played from an object URL, because the static host does not serve byte ranges and the console seeks constantly. Before a film is shown its bytes are hashed and compared with the `video_sha256` that `scene.json` records, so a stale or swapped film cannot sit under outlines made for another one. `scene.json` and the detector's box file are checked the same way, against digests computed at build time. A file that fails its check or does not load is not used: the page shows a message and a button that fetches it again, and the film or outlines that depend on it stay hidden. A browser that cannot hash, which is the case for a page served over plain HTTP from another machine, gets that message for every film.

Outlines are drawn for the frame the browser reports it has put on screen, through `requestVideoFrameCallback`, so they do not lead or trail the picture. A browser without that call plays the films without outlines and says so under the main screen. One `<video>` exists per camera; the selected camera's element is moved into the large slot, so a cut never reloads a film.
