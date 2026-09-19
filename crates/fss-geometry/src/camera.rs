use crate::GeometryError;
use crate::math::{
    IDENTITY, M3, V3, add, checked, determinant, dot, mv, normalize, scale, transpose,
};

/// Calibrated, undistorted, zero-skew pinhole intrinsics on a pixel-edge grid.
///
/// Fitting or converting lens distortion, digital crops, and stabilization is
/// deliberately outside this type. A raw distorted image is not admissible.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PinholeIntrinsics {
    width: u32,
    height: u32,
    fx: f64,
    fy: f64,
    cx: f64,
    cy: f64,
}

impl PinholeIntrinsics {
    /// Validate an exact image mode. Principal points may lie outside a crop.
    pub fn new(
        width: u32,
        height: u32,
        fx: f64,
        fy: f64,
        cx: f64,
        cy: f64,
    ) -> Result<Self, GeometryError> {
        if [fx, fy, cx, cy].iter().any(|x| !x.is_finite()) {
            return Err(GeometryError::NonFinite);
        }
        if width == 0
            || height == 0
            || width > 65536
            || height > 65536
            || fx < 1e-6
            || fy < 1e-6
            || fx > 1e9
            || fy > 1e9
            || cx.abs() > 1e9
            || cy.abs() > 1e9
        {
            return Err(GeometryError::InvalidCamera);
        }
        Ok(Self {
            width,
            height,
            fx,
            fy,
            cx,
            cy,
        })
    }

    /// Image dimensions before any display-only transforms.
    pub fn dimensions(self) -> [u32; 2] {
        [self.width, self.height]
    }
    /// Focal lengths in pixels, not millimeters.
    pub fn focal_lengths(self) -> [f64; 2] {
        [self.fx, self.fy]
    }
    /// Principal point in the declared pixel-edge coordinates.
    pub fn principal_point(self) -> [f64; 2] {
        [self.cx, self.cy]
    }
    /// Whether a finite pixel coordinate belongs to this half-open image domain.
    pub fn contains(self, pixel: [f64; 2]) -> bool {
        pixel[0].is_finite()
            && pixel[1].is_finite()
            && pixel[0] >= 0.0
            && pixel[1] >= 0.0
            && pixel[0] < f64::from(self.width)
            && pixel[1] < f64::from(self.height)
    }
    /// A positive-depth camera point projects even when it falls outside the image.
    pub fn project(self, camera_point: V3) -> Result<[f64; 2], GeometryError> {
        checked(camera_point)?;
        if camera_point[2] <= 1e-9 {
            return Err(GeometryError::BehindCamera);
        }
        let pixel = [
            self.fx * (camera_point[0] / camera_point[2]) + self.cx,
            self.fy * (camera_point[1] / camera_point[2]) + self.cy,
        ];
        if pixel.iter().any(|x| !x.is_finite()) {
            return Err(GeometryError::NonFinite);
        }
        Ok(pixel)
    }
    /// Convert a visible image observation to a unit camera bearing (+Z forward).
    pub fn bearing(self, pixel: [f64; 2]) -> Result<V3, GeometryError> {
        if !self.contains(pixel) {
            return Err(GeometryError::OutOfImage);
        }
        normalize([
            (pixel[0] - self.cx) / self.fx,
            (pixel[1] - self.cy) / self.fy,
            1.0,
        ])
    }
}

/// Proper rigid world-to-camera transform: `camera_point = R * world_point + t`.
///
/// Identity is a valid mathematical transform, not a calibration claim. Rotation
/// validation and deterministic serialized bytes do not establish physical pose
/// accuracy or cross-platform bit-identical floating-point calculations.
#[derive(Clone, Copy, PartialEq)]
pub struct RigidPose {
    rotation: M3,
    translation: V3,
}

impl std::fmt::Debug for RigidPose {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RigidPose").finish_non_exhaustive()
    }
}

impl RigidPose {
    /// The valid identity coordinate transformation; carries no evidence status.
    pub const IDENTITY: Self = Self {
        rotation: IDENTITY,
        translation: [0.0; 3],
    };
    /// Construct from a proper rotation and translation in the same world units.
    pub fn new(rotation: M3, translation: V3) -> Result<Self, GeometryError> {
        checked(translation)?;
        for row in rotation {
            checked(row)?;
        }
        if (determinant(rotation) - 1.0).abs() > 1e-8 {
            return Err(GeometryError::InvalidRotation);
        }
        for (i, a) in rotation.iter().enumerate() {
            for (j, b) in rotation.iter().enumerate() {
                let expected = if i == j { 1.0 } else { 0.0 };
                if (dot(*a, *b) - expected).abs() > 1e-8 {
                    return Err(GeometryError::InvalidRotation);
                }
            }
        }
        Ok(Self {
            rotation,
            translation,
        })
    }
    /// Construct using an optical center, not a world-to-camera translation.
    pub fn from_center(rotation: M3, center: V3) -> Result<Self, GeometryError> {
        checked(center)?;
        Self::new(rotation, scale(mv(rotation, center), -1.0))
    }
    /// Proper world-to-camera rotation, in row-major storage.
    pub fn rotation(self) -> M3 {
        self.rotation
    }
    /// World-to-camera translation. This is not the optical center.
    pub fn translation(self) -> V3 {
        self.translation
    }
    /// Camera optical center expressed in world coordinates: `-R^T t`.
    pub fn center(self) -> V3 {
        scale(mv(transpose(self.rotation), self.translation), -1.0)
    }
    /// Transform a finite world point to camera coordinates without projection.
    pub fn transform(self, point: V3) -> Result<V3, GeometryError> {
        checked(point)?;
        checked(add(mv(self.rotation, point), self.translation))
    }
    /// Project a world point into the declared undistorted image domain.
    pub fn project(
        self,
        intrinsics: PinholeIntrinsics,
        point: V3,
    ) -> Result<[f64; 2], GeometryError> {
        intrinsics.project(self.transform(point)?)
    }
    /// Build a world ray for an in-domain observation, without assigning depth.
    pub fn ray(self, intrinsics: PinholeIntrinsics, pixel: [f64; 2]) -> Result<Ray, GeometryError> {
        Ray::new(
            self.center(),
            mv(transpose(self.rotation), intrinsics.bearing(pixel)?),
        )
    }
}

/// Validated positive-distance ray with a unit world-space direction.
#[derive(Clone, Copy, PartialEq)]
pub struct Ray {
    origin: V3,
    direction: V3,
}

impl std::fmt::Debug for Ray {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ray").finish_non_exhaustive()
    }
}

impl Ray {
    /// Validate origin and normalize a nonzero finite direction.
    pub fn new(origin: V3, direction: V3) -> Result<Self, GeometryError> {
        Ok(Self {
            origin: checked(origin)?,
            direction: normalize(direction)?,
        })
    }
    /// Origin in the caller's declared world frame.
    pub fn origin(self) -> V3 {
        self.origin
    }
    /// Unit direction in that same frame.
    pub fn direction(self) -> V3 {
        self.direction
    }
    /// Evaluate a nonnegative distance in world units, not an unnormalized parameter.
    pub fn at(self, distance: f64) -> Result<V3, GeometryError> {
        if !distance.is_finite() || !(0.0..=1e12).contains(&distance) {
            return Err(GeometryError::OutOfRange);
        }
        checked(add(self.origin, scale(self.direction, distance)))
    }
}
