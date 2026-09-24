//! Deterministic person-shaped silhouette generator shared by the YOLOX conformance case, the
//! lab example and the detector-cascade scene tests (portrait 360x640, packed RGB).
//!
//! The person is drawn in local coordinates at one third scale about its foot point
//! `(foot_x, 600)` on a vertical gradient with a ground band and deterministic hash noise. With
//! `foot_x == 180` the output is byte-identical to the pinned `silhouette` conformance input.

/// Scene width and height.
pub const PERSON_SCENE_DIMENSIONS: [u32; 2] = [360, 640];

/// Packed RGB of the scene; `None` draws the empty background only.
pub fn person_scene(foot_x: Option<i64>) -> Vec<u8> {
    let (w, h) = (360_i64, 640_i64);
    let mut pixels = Vec::with_capacity((w * h * 3) as usize);
    for y in 0..h {
        for x in 0..w {
            let mut rgb: [i64; 3] = if y >= 560 {
                [90, 110, 70]
            } else {
                [
                    120 + (y * 60).div_euclid(h),
                    135 + (y * 40).div_euclid(h),
                    150 - (y * 50).div_euclid(h),
                ]
            };
            if let Some(foot_x) = foot_x {
                // Person drawn in local coordinates, one third scale about the foot point.
                let u = (x - foot_x) * 3;
                let v = 600 - (600 - y) * 3;
                let cloth = [60, 70, 110];
                let skin = [205, 165, 135];
                let pants = [45, 45, 55];
                let mut put = |mask: bool, c: [i64; 3]| {
                    if mask {
                        rgb = c;
                    }
                };
                put(u * u + (v - 150) * (v - 150) <= 900, skin);
                put(
                    u * u + (v - 140) * (v - 140) <= 1024 && v < 138,
                    [50, 35, 25],
                );
                put(u.abs() <= 12 && (176..196).contains(&v), skin);
                if (192..380).contains(&v) {
                    put(u.abs() <= 52 - ((v - 192) * 12).div_euclid(188), cloth);
                }
                if (198..370).contains(&v) {
                    let off = 54 + ((v - 198) * 14).div_euclid(172);
                    put(u >= -off - 22 && u < -off, cloth);
                    put(u > off && u <= off + 22, cloth);
                }
                put((-84..-60).contains(&u) && (370..398).contains(&v), skin);
                put(u > 60 && u <= 84 && (370..398).contains(&v), skin);
                put((-42..-5).contains(&u) && (380..585).contains(&v), pants);
                put((5..42).contains(&u) && (380..585).contains(&v), pants);
                put(
                    (-48..-2).contains(&u) && (585..600).contains(&v),
                    [20, 20, 20],
                );
                put(
                    (2..48).contains(&u) && (585..600).contains(&v),
                    [20, 20, 20],
                );
            }
            let noise = ((x * 73_856_093) ^ (y * 19_349_663)).rem_euclid(41) - 20;
            for c in rgb {
                pixels.push((c + noise).clamp(0, 255) as u8);
            }
        }
    }
    pixels
}
