# Retained-file test fixture

`retained_file_8x8.jpg` is a synthetic 8x8 uniform grayscale image (value 127), encoded
as baseline JPEG with quality 80, no optimization and no progressive scan. It contains
no camera, person, credential, private location or real sensor capture.

SHA-256: `155655331704e0e8a0791f268adb8827465e23b7d6cdddbe1872d571fb522937` (331 bytes).

Generated once with Pillow as a laboratory fixture. Pillow is not a workspace dependency
and is not invoked by the production or test execution paths. Tests use retained bytes
and the first-party Rust importer, not an external encoder or decoder at runtime.
