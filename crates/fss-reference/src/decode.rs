#![forbid(unsafe_code)]
//! Reference media decoders into deterministic [`fss_tensor::Tensor`] representations.

pub mod jpeg;

pub use jpeg::{
    DecodedImage, JPEG_DECODER_GENERATION, JPEG_DECODER_GENERATION_NUMERIC, JpegDecodeError,
    JpegDecodeLimits, JpegSubsampling, decode_baseline_jpeg,
};
