#![forbid(unsafe_code)]
//! Exact production RTSP modules, compiled natively without the reference runtime closure.

#[path = "../../../fss-reference/src/rtsp/authentication.rs"]
pub mod authentication;
#[path = "../../../fss-reference/src/rtsp/client.rs"]
pub mod client;
#[path = "../../../fss-reference/src/rtsp/datagram_archive/source.rs"]
pub mod datagram_archive;
#[path = "datagram_reconstruction.rs"]
pub mod datagram_reconstruction;
#[path = "../../../fss-reference/src/rtsp/framed.rs"]
pub mod framed;
#[path = "../../../fss-reference/src/rtsp/jpeg_client.rs"]
pub mod jpeg_client;
#[path = "../../../fss-reference/src/rtsp/live_jpeg.rs"]
pub mod live_jpeg;
#[path = "../../../fss-reference/src/rtsp/message.rs"]
pub mod message;
#[path = "../../../fss-reference/src/rtsp/sdp.rs"]
pub mod sdp;
#[path = "../../../fss-reference/src/rtsp/selection.rs"]
pub mod selection;
#[path = "../../../fss-reference/src/rtsp/tcp.rs"]
pub mod tcp;

pub use message::*;
pub use sdp::*;
