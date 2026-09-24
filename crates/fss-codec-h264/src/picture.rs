//! Decoded picture types: the internal coded-size frame buffer and the
//! public cropped [`Picture`].

use crate::DecodeError;

/// Coded-size 8-bit 4:2:0 sample planes (macroblock-aligned, uncropped).
#[derive(Clone, Debug)]
pub(crate) struct Frame {
    pub width: usize,
    pub height: usize,
    pub y: Vec<u8>,
    pub cb: Vec<u8>,
    pub cr: Vec<u8>,
}

impl Frame {
    /// Allocates a frame after the caller has enforced its budgets; the
    /// allocation itself is fallible rather than aborting.
    pub fn new(width: usize, height: usize) -> Result<Self, DecodeError> {
        let luma = width.checked_mul(height).ok_or(DecodeError::Limit)?;
        let chroma = luma / 4;
        Ok(Self {
            width,
            height,
            y: zeroed(luma)?,
            cb: zeroed(chroma)?,
            cr: zeroed(chroma)?,
        })
    }

    pub const fn chroma_width(&self) -> usize {
        self.width / 2
    }

    pub const fn chroma_height(&self) -> usize {
        self.height / 2
    }
}

fn zeroed(len: usize) -> Result<Vec<u8>, DecodeError> {
    let mut plane = Vec::new();
    plane
        .try_reserve_exact(len)
        .map_err(|_| DecodeError::Limit)?;
    plane.resize(len, 0);
    Ok(plane)
}

/// One decoded picture: tightly packed 8-bit 4:2:0 planes after SPS frame
/// cropping, in decode order (which is output order for the admitted tool
/// set). Chroma planes are `ceil(width/2) x ceil(height/2)`; with 4:2:0
/// crop units of two samples the visible size is always even.
#[derive(Clone, Eq, PartialEq)]
pub struct Picture {
    width: u32,
    height: u32,
    y: Vec<u8>,
    cb: Vec<u8>,
    cr: Vec<u8>,
    frame_num: u32,
    poc: i32,
    idr: bool,
    reference: bool,
    decode_index: u64,
}

impl std::fmt::Debug for Picture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Picture")
            .field("width", &self.width)
            .field("height", &self.height)
            .field("frame_num", &self.frame_num)
            .field("poc", &self.poc)
            .field("idr", &self.idr)
            .field("decode_index", &self.decode_index)
            .finish_non_exhaustive()
    }
}

/// Picture metadata carried alongside the planes.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PictureMeta {
    pub frame_num: u32,
    pub poc: i32,
    pub idr: bool,
    pub reference: bool,
    pub decode_index: u64,
}

impl Picture {
    /// Crops a coded frame to the visible rectangle.
    pub(crate) fn from_frame(
        frame: &Frame,
        crop: [u32; 4],
        meta: PictureMeta,
    ) -> Result<Self, DecodeError> {
        let left = usize::try_from(crop[0]).map_err(|_| DecodeError::Limit)?;
        let right = usize::try_from(crop[1]).map_err(|_| DecodeError::Limit)?;
        let top = usize::try_from(crop[2]).map_err(|_| DecodeError::Limit)?;
        let bottom = usize::try_from(crop[3]).map_err(|_| DecodeError::Limit)?;
        let width = frame
            .width
            .checked_sub(left + right)
            .ok_or(DecodeError::Malformed)?;
        let height = frame
            .height
            .checked_sub(top + bottom)
            .ok_or(DecodeError::Malformed)?;
        let y = crop_plane(&frame.y, frame.width, left, top, width, height)?;
        let chroma_stride = frame.chroma_width();
        let chroma_width = width.div_ceil(2);
        let chroma_height = height.div_ceil(2);
        let cb = crop_plane(
            &frame.cb,
            chroma_stride,
            left / 2,
            top / 2,
            chroma_width,
            chroma_height,
        )?;
        let cr = crop_plane(
            &frame.cr,
            chroma_stride,
            left / 2,
            top / 2,
            chroma_width,
            chroma_height,
        )?;
        Ok(Self {
            width: u32::try_from(width).map_err(|_| DecodeError::Limit)?,
            height: u32::try_from(height).map_err(|_| DecodeError::Limit)?,
            y,
            cb,
            cr,
            frame_num: meta.frame_num,
            poc: meta.poc,
            idr: meta.idr,
            reference: meta.reference,
            decode_index: meta.decode_index,
        })
    }

    /// Visible luma width.
    #[must_use]
    pub const fn width(&self) -> u32 {
        self.width
    }

    /// Visible luma height.
    #[must_use]
    pub const fn height(&self) -> u32 {
        self.height
    }

    /// Chroma plane width (`ceil(width / 2)`).
    #[must_use]
    pub const fn chroma_width(&self) -> u32 {
        self.width.div_ceil(2)
    }

    /// Chroma plane height (`ceil(height / 2)`).
    #[must_use]
    pub const fn chroma_height(&self) -> u32 {
        self.height.div_ceil(2)
    }

    /// Luma samples, row stride = `width`.
    #[must_use]
    pub fn luma(&self) -> &[u8] {
        &self.y
    }

    /// Cb samples, row stride = `chroma_width`.
    #[must_use]
    pub fn cb(&self) -> &[u8] {
        &self.cb
    }

    /// Cr samples, row stride = `chroma_width`.
    #[must_use]
    pub fn cr(&self) -> &[u8] {
        &self.cr
    }

    /// `frame_num` of the coded picture.
    #[must_use]
    pub const fn frame_num(&self) -> u32 {
        self.frame_num
    }

    /// Picture order count (top field order count for frames).
    #[must_use]
    pub const fn poc(&self) -> i32 {
        self.poc
    }

    /// Whether the picture was an IDR picture.
    #[must_use]
    pub const fn is_idr(&self) -> bool {
        self.idr
    }

    /// Whether the picture was marked as a reference (`nal_ref_idc != 0`).
    #[must_use]
    pub const fn is_reference(&self) -> bool {
        self.reference
    }

    /// Zero-based index of this picture in decode order since the decoder
    /// was created.
    #[must_use]
    pub const fn decode_index(&self) -> u64 {
        self.decode_index
    }

    /// Packed planar I420 bytes: Y, then Cb, then Cr (FFmpeg `yuv420p`
    /// rawvideo layout).
    #[must_use]
    pub fn to_i420(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.y.len() + self.cb.len() + self.cr.len());
        out.extend_from_slice(&self.y);
        out.extend_from_slice(&self.cb);
        out.extend_from_slice(&self.cr);
        out
    }

    /// SHA-256 over [`Self::to_i420`].
    #[must_use]
    pub fn i420_sha256(&self) -> [u8; 32] {
        fss_core::ContentDigest::sha256(&self.to_i420()).bytes()
    }
}

fn crop_plane(
    plane: &[u8],
    stride: usize,
    left: usize,
    top: usize,
    width: usize,
    height: usize,
) -> Result<Vec<u8>, DecodeError> {
    let mut out = Vec::new();
    out.try_reserve_exact(width * height)
        .map_err(|_| DecodeError::Limit)?;
    for row in 0..height {
        let start = (top + row) * stride + left;
        let line = plane
            .get(start..start + width)
            .ok_or(DecodeError::Malformed)?;
        out.extend_from_slice(line);
    }
    Ok(out)
}
