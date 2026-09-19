# Authored detector-row plumbing fixture

This is an explicitly authored arithmetic graph, not trained weights or a useful detector.
The one-channel 8x8 image is max-pooled over the whole image, multiplied by the explicit
scalar zero parameter, added to 18 explicit bias values, and reshaped to [3,6].
The rows are [0.125,0.125,0.5,0.5,0.9,0], the same box with score 0.8 and class 0,
and the same box with score 0.7 and class 1. Class-aware NMS keeps rows 0 and 2.
The graph uses generation 3, unit-scale luma preprocessing, the existing frozen operator
table, and exact big-endian F32 parameters. It contains no externally sourced model data.

Model bytes: 981. Model SHA-256:
`2b1c64990f1c1820b3bdb77ea32cc25b2fff484db11fe7d68b0e1f04bd2c45c8`.
Canonical graph SHA-256:
`3abbec21c02e950f62b31c526ecfd0844a053990096c717e240e547b83902ceb`.
Git blob identity: `cf73c2902a3f8fee6a67eb0cf8bf1be5303028c0`.
The model envelope, graph checksum, parameter counts, exact EOF and uploaded blob identity
were independently checked using Python. Rust execution remains a required test.
