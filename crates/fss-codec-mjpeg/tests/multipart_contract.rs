#![forbid(unsafe_code)]
use fss_codec_mjpeg::{ComponentInterpretation, DecodeBudget, DecodeError, DecodeLimits};
use fss_codec_mjpeg::multipart::*;
use fss_codec_mjpeg::stream::StreamBasis;
use fss_core::ContentDigest;
use std::sync::atomic::AtomicBool;

type Test = Result<(), Box<dyn std::error::Error>>;
const JPEG: &[u8] = include_bytes!("fixtures/gray.jpg");
const TYPE: &str = "multipart/x-mixed-replace; boundary=\"camera:7\"";
fn basis() -> StreamBasis { StreamBasis { source: [5;32], generation: 4 } }
fn parser() -> Result<MultipartStream, MultipartError> {
    MultipartStream::new(basis(), TYPE, MultipartLimits::default(), &mut DecodeBudget::new(10000))
}
fn entity(images: &[&[u8]], length: bool) -> Vec<u8> {
    let mut out = b"--camera:7\r\n".to_vec();
    for (i, image) in images.iter().enumerate() {
        out.extend_from_slice(b"Content-Type: image/jpeg\r\nX-Timestamp: untrusted\r\n");
        if length { out.extend_from_slice(format!("Content-Length: {}\r\n",image.len()).as_bytes()); }
        out.extend_from_slice(b"\r\n"); out.extend_from_slice(image);
        out.extend_from_slice(b"\r\n--camera:7");
        if i+1 == images.len() { out.extend_from_slice(b"--"); }
        out.extend_from_slice(b"\r\n");
    }
    out
}
fn collect(data: &[u8], chunk: usize) -> Result<(Vec<MultipartFrame>,MultipartEnd),Box<dyn std::error::Error>> {
    let mut p = parser()?; let mut budget = DecodeBudget::new(100_000_000);
    let mut frames = Vec::new(); let mut at = 0;
    while at < data.len() {
        let end = at.saturating_add(chunk).min(data.len());
        let step = p.push(at as u64, &data[at..end], &mut budget)?;
        assert!(step.consumed > 0); at += step.consumed;
        if let Some(frame) = step.frame { frames.push(frame); }
    }
    let finish = p.finish(&mut budget)?;
    if let Some(frame) = finish.frame { frames.push(frame); }
    Ok((frames,finish.end))
}
#[test]
fn length_and_delimiter_parts_decode_and_preserve_source_ranges() -> Test {
    for lengths in [false,true] {
        let data = entity(&[JPEG,JPEG],lengths); let (frames,end) = collect(&data,7)?;
        assert_eq!(frames.len(),2); assert_eq!(end.frames,2); assert_eq!(end.bytes,data.len() as u64);
        for (i, frame) in frames.iter().enumerate() {
            let r = frame.receipt(); assert_eq!(r.ordinal,i as u64+1); assert_eq!(r.basis,basis());
            assert_eq!(r.content_type_sha256,ContentDigest::sha256(TYPE.as_bytes()).bytes());
            assert_eq!(frame.bytes(),JPEG); assert_eq!(&data[r.jpeg_range[0] as usize..r.jpeg_range[1] as usize],JPEG);
            assert_eq!(&data[r.headers_range[0] as usize..r.headers_range[1] as usize],frame.headers());
            assert_eq!(&data[r.opening_range[0] as usize..r.opening_range[1] as usize],frame.opening_bytes());
            assert_eq!(&data[r.closing_range[0] as usize..r.closing_range[1] as usize],frame.closing_bytes());
            assert_eq!(r.declared_length,lengths.then_some(JPEG.len())); assert_eq!(r.closes_entity,i==1);
            assert_eq!(frame.decode(ComponentInterpretation::Grayscale,DecodeLimits::default(),&mut DecodeBudget::new(10_000_000))?.dimensions(),[17,13]);
        }
        assert_eq!(frames[0].receipt().closing_range,frames[1].receipt().opening_range);
    } Ok(())
}
#[test]
fn every_two_chunk_split_preserves_exact_parts() -> Test {
    let data = entity(&[JPEG,JPEG],true);
    for split in 0..=data.len() {
        let mut p = parser()?; let mut b = DecodeBudget::new(10_000_000); let mut parts = Vec::new(); let mut at=0;
        for stop in [split,data.len()] {
            while at < stop {
                let step=p.push(at as u64,&data[at..stop],&mut b)?; assert!(step.consumed>0); at+=step.consumed;
                if let Some(frame)=step.frame {parts.push(frame);}
            }
        }
        let end=p.finish(&mut b)?; assert!(end.frame.is_none()); assert_eq!(parts.len(),2);
        assert!(parts.iter().all(|p|p.bytes()==JPEG));
    } Ok(())
}
#[test]
fn missing_final_crlf_is_accepted_only_at_explicit_eof() -> Test {
    let mut data=entity(&[JPEG],false); data.truncate(data.len()-2);
    let mut p=parser()?; let mut b=DecodeBudget::new(1_000_000);
    let step=p.push(0,&data,&mut b)?; assert!(step.frame.is_none()); assert_eq!(p.completed_frames(),0);
    let end=p.finish(&mut b)?; assert_eq!(end.frame.ok_or("missing final part")?.bytes(),JPEG); assert_eq!(end.end.frames,1);
    assert_eq!(p.finish(&mut b).err().ok_or("repeated EOF")?.error,MultipartError::Closed); Ok(())
}
#[test]
fn all_prefixes_before_a_complete_closing_delimiter_fail() {
    let data=entity(&[JPEG],false);
    for end in 0..data.len()-2 { assert!(collect(&data[..end],3).is_err(),"prefix {end}"); }
}
#[test]
fn preamble_epilogue_and_boundary_padding_are_retained() -> Test {
    let body=entity(&[JPEG],true);
    let mut data=b"owner-selected preamble\r\n".to_vec(); data.extend_from_slice(&body[..body.len()-2]);
    data.extend_from_slice(b" \t\r\nepilogue");
    let (frames,end)=collect(&data,1)?; assert_eq!(frames.len(),1);
    assert_eq!(end.preamble.bytes(),b"owner-selected preamble"); assert_eq!(end.epilogue.bytes(),b"epilogue");
    assert_eq!(frames[0].opening_bytes(),b"\r\n--camera:7\r\n");
    assert!(frames[0].closing_bytes().ends_with(b"-- \t\r\n")); Ok(())
}
#[test]
fn jpeg_marker_like_metadata_is_not_a_mime_boundary() -> Test {
    let payload=b"false\xff\xd9\r\n--different\r\n\xff\xd8";
    let mut image=vec![255,216,255,225]; image.extend_from_slice(&((payload.len()+2) as u16).to_be_bytes());
    image.extend_from_slice(payload); image.extend_from_slice(&JPEG[2..]);
    let data=entity(&[&image],false); let (parts,_)=collect(&data,1)?;
    assert_eq!(parts[0].bytes(),image);
    parts[0].decode(ComponentInterpretation::Grayscale,DecodeLimits::default(),&mut DecodeBudget::new(1_000_000))?;
    Ok(())
}
#[test]
fn wrong_or_duplicate_lengths_and_unsupported_encodings_fail() {
    for header in ["Content-Length: 4\r\n","Content-Length: 9999\r\n",
        "Content-Length: -1\r\n","Content-Length: 184467440737095516160\r\n",
        "Content-Length: 351\r\ncontent-length: 351\r\n","Content-Transfer-Encoding: base64\r\n",
        "Content-Encoding: gzip\r\n","Transfer-Encoding: chunked\r\n"," Folded: no\r\n",
        "X-Test: a\r\nx-test: b\r\n"] {
        let mut data=b"--camera:7\r\nContent-Type: image/jpeg\r\n".to_vec(); data.extend_from_slice(header.as_bytes());
        data.extend_from_slice(b"\r\n"); data.extend_from_slice(JPEG); data.extend_from_slice(b"\r\n--camera:7--\r\n");
        assert!(collect(&data,11).is_err(),"accepted {header}");
    }
}
#[test]
fn missing_type_nonjpeg_type_and_bare_lf_headers_are_rejected() {
    for headers in [b"X-Test: yes\r\n\r\n".as_slice(), b"Content-Type: text/html\r\n\r\n",
        b"Content-Type: image/jpeg\n\n",b"Content-Type: image/jpeg;anything=1\r\n\r\n"] {
        let mut data=b"--camera:7\r\n".to_vec(); data.extend_from_slice(headers); data.extend_from_slice(JPEG);
        data.extend_from_slice(b"\r\n--camera:7--\r\n"); assert!(collect(&data,1).is_err());
    }
}
#[test]
fn boundary_prefix_collision_refuses_competing_interpretations() {
    let data=b"--camera:7suffix\r\n";
    assert!(collect(data,1).is_err());
    let payload=b"\r\n--camera:7suffix\r\n";
    let mut jpeg=vec![255,216,255,225];jpeg.extend_from_slice(&((payload.len()+2) as u16).to_be_bytes());
    jpeg.extend_from_slice(payload);jpeg.extend_from_slice(&JPEG[2..]);
    assert!(collect(&entity(&[&jpeg],true),1).is_err());
}
#[test]
fn boundary_configuration_never_guesses_or_strips_prefixes() -> Test {
    for value in ["image/jpeg", "multipart/x-mixed-replace", "multipart/x-mixed-replace; boundary=",
        "multipart/x-mixed-replace; boundary=camera:7", "multipart/x-mixed-replace; boundary=\"bad \"",
        "multipart/x-mixed-replace; boundary=a; boundary=b", "multipart/x-mixed-replace; boundary=\"a\\b\"",
        "multipart/x-mixed-replace; boundary=x\r\nAnything: x"] {
        assert!(MultipartStream::new(basis(),value,MultipartLimits::default(),&mut DecodeBudget::new(10000)).is_err());
    }
    let mut p=MultipartStream::new(basis(),"MULTIPART/X-MIXED-REPLACE; BOUNDARY=--real",MultipartLimits::default(),&mut DecodeBudget::new(10000))?;
    let mut data=b"----real\r\nContent-Type: image/jpeg\r\n\r\n".to_vec();data.extend_from_slice(JPEG);data.extend_from_slice(b"\r\n----real--\r\n");
    assert_eq!(p.push(0,&data,&mut DecodeBudget::new(1_000_000))?.frame.ok_or("missing part")?.bytes(),JPEG); Ok(())
}
#[test]
fn raw_part_is_not_an_entropy_validation_claim() -> Test {
    let jpeg=[255,216,255,217]; let (parts,_)=collect(&entity(&[&jpeg],true),5)?;
    assert!(parts[0].decode(ComponentInterpretation::Grayscale,DecodeLimits::default(),&mut DecodeBudget::new(10000)).is_err()); Ok(())
}
#[test]
fn offset_failure_latches_and_retains_exact_unpublished_bytes() -> Test {
    let data=entity(&[JPEG],true);let mut p=parser()?;let mut b=DecodeBudget::new(1_000_000);
    p.push(0,&data[..120],&mut b)?;
    let failure=p.push(119,&data[120..],&mut b).err().ok_or("offset accepted")?;
    assert_eq!((failure.error,failure.consumed,failure.next_offset),(MultipartError::Offset,0,120));
    assert_eq!(p.push(120,&data[120..],&mut b).err().ok_or("resumed")?.error,MultipartError::Poisoned);
    let recovery=p.abort(); let mut spans:Vec<_>=recovery.spans.iter().filter(|s|!s.bytes().is_empty()).collect();spans.sort_by_key(|s|s.range()[0]);
    let mut reconstructed=Vec::new();for span in spans {assert_eq!(span.range()[0],reconstructed.len() as u64);reconstructed.extend_from_slice(span.bytes());}
    assert_eq!(reconstructed,&data[..120]);Ok(())
}
#[test]
fn cancellation_and_work_exhaustion_do_not_emit_a_part() -> Test {
    let data=entity(&[JPEG],true);let mut p=parser()?;let flag=AtomicBool::new(true);
    let e=p.push(0,&data,&mut DecodeBudget::cancellable(1_000_000,&flag)).err().ok_or("cancel ignored")?;
    assert_eq!((e.error,e.consumed),(MultipartError::Work(DecodeError::Cancelled),0));
    let mut p=parser()?;let e=p.push(0,&data,&mut DecodeBudget::new(16)).err().ok_or("work ignored")?;
    assert_eq!((e.error,e.consumed),(MultipartError::Work(DecodeError::BudgetExhausted),2));
    assert_eq!(p.abort().spans[3].bytes(),&data[..2]);Ok(())
}
#[test]
fn header_and_wrapper_ceilings_fail_without_silent_omission() -> Test {
    for limits in [MultipartLimits{header_bytes:4,..MultipartLimits::default()},
        MultipartLimits{frame_bytes:JPEG.len()-1,..MultipartLimits::default()}] {
        let mut p=MultipartStream::new(basis(),TYPE,limits,&mut DecodeBudget::new(10000))?;
        assert!(p.push(0,&entity(&[JPEG],true),&mut DecodeBudget::new(10_000_000)).is_err());assert_eq!(p.completed_frames(),0);
    }
    let mut p=MultipartStream::new(basis(),TYPE,MultipartLimits{wrapper_bytes:0,..MultipartLimits::default()},&mut DecodeBudget::new(10000))?;
    let data=entity(&[JPEG],false);p.push(0,&data,&mut DecodeBudget::new(1_000_000))?;
    assert!(p.push(data.len() as u64,b"x",&mut DecodeBudget::new(1000)).is_err());assert!(p.finish(&mut DecodeBudget::new(1000)).is_err());Ok(())
}
#[test]
fn maximum_boundary_padding_fits_exact_payload_ceiling() -> Test {
    let name="b".repeat(70);let ct=format!("multipart/x-mixed-replace; boundary={name}");
    let mut data=format!("--{name}\r\nContent-Type: image/jpeg\r\nContent-Length: {}\r\n\r\n",JPEG.len()).into_bytes();data.extend_from_slice(JPEG);
    data.extend_from_slice(format!("\r\n--{name}--{}\r\n"," ".repeat(64)).as_bytes());
    let mut p=MultipartStream::new(basis(),&ct,MultipartLimits{frame_bytes:JPEG.len(),..MultipartLimits::default()},&mut DecodeBudget::new(10000))?;
    assert_eq!(p.push(0,&data,&mut DecodeBudget::new(10_000_000))?.frame.ok_or("maximum delimiter lost")?.bytes(),JPEG);Ok(())
}
#[test]
fn stop_after_one_part_preserves_unread_suffix_and_later_errors() -> Test {
    let first=entity(&[JPEG,JPEG],true);let mut data=first.clone();
    let at=data.windows(2).rposition(|w|w==[255,217]).ok_or("missing EOI")?;data[at+1]=0;
    let mut p=parser()?;let mut b=DecodeBudget::new(1_000_000);let one=p.push(0,&data,&mut b)?;
    assert!(one.frame.is_some());assert!(one.consumed<data.len());
    assert!(p.push(one.consumed as u64,&data[one.consumed..],&mut b).is_err());assert_eq!(p.completed_frames(),1);assert!(p.finish(&mut b).is_err());Ok(())
}
