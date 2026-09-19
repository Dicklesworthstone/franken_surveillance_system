use crate::GeometryError;

pub(crate) type V3 = [f64; 3];
pub(crate) type M3 = [[f64; 3]; 3];
pub(crate) const IDENTITY: M3 = [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]];

pub(crate) fn checked(v: V3) -> Result<V3, GeometryError> {
    if v.iter().any(|x| !x.is_finite()) {
        return Err(GeometryError::NonFinite);
    }
    if v.iter().any(|x| x.abs() > 1e12) {
        return Err(GeometryError::OutOfRange);
    }
    Ok(v)
}
pub(crate) fn add(a: V3, b: V3) -> V3 {
    [a[0] + b[0], a[1] + b[1], a[2] + b[2]]
}
pub(crate) fn sub(a: V3, b: V3) -> V3 {
    [a[0] - b[0], a[1] - b[1], a[2] - b[2]]
}
pub(crate) fn scale(a: V3, s: f64) -> V3 {
    [a[0] * s, a[1] * s, a[2] * s]
}
pub(crate) fn dot(a: V3, b: V3) -> f64 {
    a[0] * b[0] + a[1] * b[1] + a[2] * b[2]
}
pub(crate) fn cross(a: V3, b: V3) -> V3 {
    [
        a[1] * b[2] - a[2] * b[1],
        a[2] * b[0] - a[0] * b[2],
        a[0] * b[1] - a[1] * b[0],
    ]
}
pub(crate) fn norm(a: V3) -> f64 {
    a[0].hypot(a[1]).hypot(a[2])
}
pub(crate) fn normalize(a: V3) -> Result<V3, GeometryError> {
    checked(a)?;
    let length = norm(a);
    if length <= 1e-12 {
        return Err(GeometryError::Degenerate);
    }
    Ok(scale(a, 1.0 / length))
}
pub(crate) fn mv(a: M3, b: V3) -> V3 {
    [dot(a[0], b), dot(a[1], b), dot(a[2], b)]
}
pub(crate) fn transpose(a: M3) -> M3 {
    [
        [a[0][0], a[1][0], a[2][0]],
        [a[0][1], a[1][1], a[2][1]],
        [a[0][2], a[1][2], a[2][2]],
    ]
}
pub(crate) fn determinant(a: M3) -> f64 {
    dot(a[0], cross(a[1], a[2]))
}
