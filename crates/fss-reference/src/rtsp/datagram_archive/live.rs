#![forbid(unsafe_code)]
//! Native source custody before further media progress.
//! AVC retains its existing owner; HEVC and JPEG framed input use the same archive.

use super::*;

mod capture;
mod framed;
pub use capture::*;
