#![forbid(unsafe_code)]
//! Native source custody before further media progress.
//! AVC capture retains its existing owner; HEVC framed input uses the same archive.

use super::*;

mod capture;
mod framed;
pub use capture::*;
