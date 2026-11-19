# Share card artwork

The camera and glass plates are editorial illustrations generated with the built-in ImageGen tool. The share cards combine these JPEG sources with typeset captions at build time.

## Camera optics

`camera-optics.jpg`

Product-mockup editorial plate for the Franken Surveillance field guide. A modest unbranded cylindrical white outdoor Wi-Fi camera on its little ball bracket on a workbench, huge detailed blue-black glass eye, the camera faces the viewer at three-quarter angle. Behind it floats an artistic transparent optical exploded view of the lens with three circular glass elements, refracted mint light and a crisp amber pin light. Industrial design editorial photography, beautifully crafted physical objects, deep midnight teal charcoal studio, lush cinematic light, rich black shadows and light film grain. Portrait-friendly composition centered fully on the object with breathing room, square crop. No text, labels, digits, brands, typography or interface.

## Event ledger

`ledger-glass.jpg`

Stylized-concept editorial product photograph for a museum exhibition about immutable camera evidence. A small stack of four thick, beautifully edge-polished square dark glass photographic plates levitates in an exploded isometric view above a dark petroleum-green lab bench. Each transparent plate carries a different ghostly etched fragment of one modest house's front porch, a tiny square image tile, or a bare circuit trace. All align into a single miniature architectural image seen through the layers. A narrow amber laser grazes their edges, rich cyan caustics and sharp etched detail, silver-green light, dark air around the stack, physically plausible reflections. Hero object centered, square crop, tactile high-end macro photography, generous negative space around object. No text, digits, symbols resembling letters, people, or logos.

## Property views

The earlier parcel cover is retained as `public/motion/arrival.webp` with its JPEG rendition in `art/arrival.jpg`. The motion study’s share cards use the reproducible WebGL exposure `public/motion/pose.jpg`. The ImageGen brief for the opening illustration follows.

Cinematic editorial photograph, a panoramic 16:9 feature cover for an architectural magazine about the science of observing an ordinary residential delivery. A believable adult courier wearing a muted terracotta work jacket, charcoal trousers and a knit cap, in full figure at the RIGHT side of frame, walking with a small tan cardboard parcel towards a beautiful modest contemporary craftsman house porch. Ground-level three-quarter view across a dark courtyard, refined dark green timber cladding, large amber lit windows, tall pines, wet dark flagstones reflecting the amber lights. Twilight, soft blue smoke in trees, layered deep blue shadows, warm late light picking out folds of the jacket. The person should be clearly readable, about 45 percent of image height at x=72%, lifelike and naturally posed, human scale. The left 40% is mostly the unlit almost black evergreen garden and shadowed wall, deliberately quiet for a title to be typeset later. High-end film production still, atmospheric and restrained, fine 35mm grain, tactile leaf/wood/cloth details. No text, no graphics, no logos, no fake surveillance overlays, no lettering, no borders.

`house.jpg` is a JPEG rendition of the existing Juniper House opening illustration. `site-plan.jpg` is the overhead 3D model rendered by `node scripts/render-films.mjs --wall`. The film strips and paired entry frames come from the published camera fixtures.

## The courtyard

The home and courtyard share cards use our WebGL renders. The passer and receiver are derived from `Male_Adult_01` and `Female_Adult_03` in Microsoft’s Rocketbox collection at commit `0943055db6ec570bcef9f2c8b41c9e5467c808f9`. The original skeletal meshes and weights were converted to local GLB files with Blender 4.3. The materials use downsampled original albedo and cutout textures. The pass poses are computed in the browser. Both GLBs and the upstream MIT notice are distributed with the exhibit. [Source models](https://github.com/microsoft/Microsoft-Rocketbox/tree/0943055db6ec570bcef9f2c8b41c9e5467c808f9/Assets/Avatars/Adults) · [License](../public/court/ROCKETBOX-LICENSE.txt)

The courtyard lighting uses Poly Haven’s CC0 *Spruit Sunrise* environment at 1K. The court, architecture, benches, near trees and ball are constructed in Three.js. The distant garden is an ImageGen matte, generated from the brief below. The capture index pins all four source assets and the reference films and stills by SHA-256. [HDR source](https://polyhaven.com/a/spruit_sunrise) · [Capture index](../public/court/capture.json)

Create a very wide panoramic photographic garden background texture for a 3D architectural visualization. Horizontal landscape 3:1 if possible. Straight-on eye-level view into a beautifully landscaped Northern California private garden, late golden afternoon. The entire frame is filled with layered natural foliage from left to right: deep forest-green olive trees and tall dark coastal pine trunks, sage olive leaves, gilded patches of Japanese maple, dense low shrubs, very fine leaf detail and shafts of amber light. Moody green shadows and visible depth between trees, confident color harmony. Only tiny glimpses of muted blue-gray sky at the very top; lush shrubs cover the entire bottom. Middle distance through far distance, shot on a 70mm lens, subtle film grain, premium architectural photography. No buildings, no walls, no foreground objects, no people, no sculpture, no court, no text, no graphics. This is a garden matte to sit beyond an architectural arcade in a browser 3D environment.

## Optical field guide posters

Three ImageGen compositions provide the editorial artwork for the poster collection. `juniper-model.jpg` depicts an architectural miniature with three overlapping camera views. `night-garden.jpg` depicts a raccoon under a porch light. A single museum instrument drawer supplies four close views for the belief, handoff, owner response, and poster room cards. The drawer contains a prism splitting light, a clipped set of photographs, a brass bell and a roll of film. These illustrations are credited on the cinematic covers or paired with sourced fixture results on the instrument cards.

The photographic contact sheets use the actual WebGL renders, encoded films, and camera evidence. The stereo cover includes the new sightline render. Next.js typesets each plate in local Instrument Serif and IBM Plex Mono and rasterizes both delivery sizes with ImageResponse. The [poster room](https://franken-surveillance.com/exhibits/poster-room/) exposes the full-resolution images.
