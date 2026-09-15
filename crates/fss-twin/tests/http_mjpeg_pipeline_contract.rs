#![forbid(unsafe_code)]
use fss_codec_mjpeg::{ComponentInterpretation as Color, DecodeBudget, DecodeLimits};
use fss_core::ContentDigest;
use fss_geometry::{PinholeIntrinsics, WorkBudget};
use fss_twin::foreground::{BackgroundPolicy, ForegroundPolicy};
use fss_twin::foreground::pipeline::FrameCapture;
use fss_twin::mjpeg::*;
use fss_twin::rectification::{LensDistortion, LumaRange, RectificationPlan, RectificationSpec};

type Test = Result<(),Box<dyn std::error::Error>>;
const BACKGROUND: &[u8] = include_bytes!("../../fss-codec-mjpeg/tests/fixtures/background.jpg");
const QUERY: &[u8] = include_bytes!("../../fss-codec-mjpeg/tests/fixtures/gray.jpg");
fn binding(encoded: &[u8], mask: &[u8], exposure: u8) -> JpegFrameBinding {
    JpegFrameBinding { encoded_sha256:ContentDigest::sha256(encoded).bytes(), exposure:[exposure;32],
        allowed_mask:ContentDigest::sha256(mask).bytes(),camera_image_domain:[7;32],
        calibration:[8;32],interpretation:Color::Grayscale }
}
fn plan(budget: &mut WorkBudget<'_>) -> Result<RectificationPlan,Box<dyn std::error::Error>> {
    let k=PinholeIntrinsics::new(17,13,20.0,20.0,8.5,6.5)?;
    Ok(RectificationPlan::compile(RectificationSpec { source:k,target:k,distortion:LensDistortion::Pinhole,
        maximum_radius:1.0,source_domain:decoded_image_domain([7;32],Color::Grayscale),
        calibration:[8;32],range:LumaRange::Full },budget)?)
}
fn baseline(plan: &RectificationPlan, mask: &[u8], decoder: &mut DecodeBudget<'_>, geometry: &mut WorkBudget<'_>)
    -> Result<JpegBackground,Box<dyn std::error::Error>> {
    let a=decode_rectified(plan,BACKGROUND,mask,binding(BACKGROUND,mask,1),DecodeLimits::default(),decoder,geometry)?;
    let b=decode_rectified(plan,BACKGROUND,mask,binding(BACKGROUND,mask,2),DecodeLimits::default(),decoder,geometry)?;
    let c=decode_rectified(plan,BACKGROUND,mask,binding(BACKGROUND,mask,3),DecodeLimits::default(),decoder,geometry)?;
    let references = [
        JpegReference{image:&a,capture:FrameCapture{camera:1,clock:2,capture:[10,10]}},
        JpegReference{image:&b,capture:FrameCapture{camera:1,clock:2,capture:[20,20]}},
        JpegReference{image:&c,capture:FrameCapture{camera:1,clock:2,capture:[30,30]}},
    ];
    Ok(JpegBackground::build(plan,&references,
        BackgroundPolicy {selection_evidence:[9;32],validity:[0,100],maximum_spread:0},geometry)?)
}
fn policy() -> ForegroundPolicy {
    ForegroundPolicy {minimum_change:10,minimum_area:1,maximum_regions:128,widespread_per_mille:900}
}
use fss_codec_mjpeg::http::{HttpEvent,HttpLimits,HttpResponseStream};
use fss_codec_mjpeg::http_mjpeg::{HttpJpegFrame,HttpMultipartStream};
use fss_codec_mjpeg::multipart::MultipartLimits;
use fss_codec_mjpeg::stream::StreamBasis;
use fss_twin::mjpeg::http::{HttpQuery,detect_http};
fn framed()->Result<(Vec<u8>,HttpJpegFrame),Box<dyn std::error::Error>> {
    let mut entity=b"--f\r\nContent-Type: image/jpeg\r\n\r\n".to_vec();
    entity.extend_from_slice(QUERY);entity.extend_from_slice(b"\r\n--f--\r\n");
    let mut wire=b"HTTP/1.1 200 OK\r\nContent-Type: multipart/x-mixed-replace; boundary=f\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
    for chunk in entity.chunks(17){wire.extend_from_slice(format!("{:x}\r\n",chunk.len()).as_bytes());wire.extend_from_slice(chunk);wire.extend_from_slice(b"\r\n");}
    wire.extend_from_slice(b"0\r\n\r\n");
    let scope=StreamBasis{source:ContentDigest::sha256(&wire).bytes(),generation:1};
    let mut h=HttpResponseStream::new(scope,HttpLimits::default())?;
    let mut p=None;let mut frame=None;let mut b=DecodeBudget::new(100_000_000);
    while (h.next_offset() as usize)<wire.len(){
        let s=h.push(h.next_offset(),&wire[h.next_offset() as usize..],&mut b)?;
        match s.event {
            Some(HttpEvent::Head(head))=>p=Some(HttpMultipartStream::new(&head,MultipartLimits::default(),4096,&mut b)?),
            Some(HttpEvent::Data(data))=>{let mut at=0;while at<data.bytes().len(){
                let s=p.as_mut().ok_or("missing MIME")?.push(&data,at,&mut b)?;at+=s.consumed;if s.frame.is_some(){frame=s.frame;}
            }},_=>(),
        }
    }
    let end=p.as_mut().ok_or("no MIME")?.finish(h.finish(&mut b)?,&mut b)?;
    if end.final_frame.is_some(){frame=end.final_frame;}
    Ok((wire,frame.ok_or("no JPEG")?))
}
#[test]
fn chunked_response_reaches_masked_foreground_with_original_wire_spans()->Test {
    let (wire,frame)=framed()?;let mut d=DecodeBudget::new(100_000_000);let mut g=WorkBudget::new(100_000_000);
    let p=plan(&mut g)?;let mut mask=vec![1;221];mask[55]=0;let model=baseline(&p,&mask,&mut d,&mut g)?;
    let result=detect_http(&model,&p,HttpQuery{expected_response:frame.head().wire,frame:&frame,mask:&mask,
        binding:binding(QUERY,&mask,4),capture:FrameCapture{camera:1,clock:2,capture:[40,40]},
        policy:policy(),limits:DecodeLimits::default()},&mut d,&mut g)?;
    let reconstructed:Vec<u8>=result.source().source_spans().iter().flat_map(|r|
        wire[r.wire_range[0] as usize..r.wire_range[1] as usize].iter().copied()).collect();
    assert_eq!(reconstructed,QUERY);assert!(result.source().source_spans().len()>1);
    assert!(!result.foreground().analysis().report().regions().is_empty());
    assert_eq!(result.foreground().analysis().frame().allowed()[55],0);
    assert_eq!(result.foreground().receipt().source.exposure,[4;32]);Ok(())
}
#[test]
fn stale_http_generation_is_refused_before_decoding()->Test {
    let (_,frame)=framed()?;let mut d=DecodeBudget::new(100_000_000);let mut g=WorkBudget::new(100_000_000);
    let p=plan(&mut g)?;let mask=vec![1;221];let model=baseline(&p,&mask,&mut d,&mut g)?;
    let result=detect_http(&model,&p,HttpQuery{expected_response:StreamBasis{generation:2,..frame.head().wire},frame:&frame,mask:&mask,
        binding:binding(QUERY,&mask,4),capture:FrameCapture{camera:1,clock:2,capture:[40,40]},
        policy:policy(),limits:DecodeLimits::default()},&mut DecodeBudget::new(0),&mut g);
    assert!(matches!(result,Err(JpegPipelineError::BasisMismatch)));Ok(())
}
