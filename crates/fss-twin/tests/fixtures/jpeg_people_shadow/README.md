# Procedural JPEG execution fixture

`texture.jpg` is an 80x144, 8-bit grayscale baseline JPEG. The source luma is
`40 + ((3*x + 2*y + (x*y)%19)%176)` for x=0..79, y=0..143. It was encoded offline
with Pillow quality=85, optimize=False, progressive=False. Its SHA-256 is
`3f668bfc6e595276e425f30ee882127abe0596b99a4e24523f9503458d8aab8e`.

The fixture contains no person or real camera evidence. The shadow executable's
unit tests use it with actual pretrained coefficients to test native decode,
health, scanning, tracking/zone receipt flow and failure boundaries. The very low
test margin gate is a plumbing assumption, NOT a detector operating point.
There is no Pillow or Python runtime dependency.
