#![forbid(unsafe_code)]
//! Read-only, hash-checked HTTP/MIME/JPEG integration harness; no networking.
use fss_codec_mjpeg::{ComponentInterpretation,DecodeBudget,DecodeLimits};
use fss_codec_mjpeg::http::{HttpEvent,HttpLimits,HttpResponseStream};
use fss_codec_mjpeg::http_mjpeg::{HttpJpegFrame,HttpMultipartStream};
use fss_codec_mjpeg::multipart::MultipartLimits;
use fss_codec_mjpeg::stream::StreamBasis;
use fss_core::ContentDigest;
use std::error::Error;
use std::io::Read;
fn hash(text:&str)->Result<[u8;32],Box<dyn Error>> {
    if text.len()!=64 || !text.bytes().all(|b|b.is_ascii_digit() || (b'a'..=b'f').contains(&b)){return Err("invalid SHA-256".into());}
    let mut out=[0;32];for (i,b) in out.iter_mut().enumerate(){*b=u8::from_str_radix(&text[i*2..i*2+2],16)?;}Ok(out)
}
fn hex(bytes:[u8;32])->String {bytes.iter().map(|b|format!("{b:02x}")).collect()}
fn emit(frame:&HttpJpegFrame,color:ComponentInterpretation,budget:&mut DecodeBudget<'_>)->Result<(),Box<dyn Error>> {
    let image=frame.decode(color,DecodeLimits::default(),budget)?;
    let id=frame.part().receipt();
    println!("frame={} encoded={} luma={} width={} height={} spans={}",id.ordinal,hex(id.encoded_sha256),
        hex(image.receipt().luma_sha256),image.dimensions()[0],image.dimensions()[1],frame.source_spans().len());
    for span in frame.source_spans(){println!("map frame={} jpeg_start={} jpeg_end={} wire_start={} wire_end={}",
        id.ordinal,span.jpeg_range[0],span.jpeg_range[1],span.wire_range[0],span.wire_range[1]);}Ok(())
}
fn main()->Result<(),Box<dyn Error>> {
    let args:Vec<_>=std::env::args().collect();
    if !(4..=5).contains(&args.len()){return Err("usage: decode_http INPUT SHA256 grayscale|ycbcr [FRAGMENT_BYTES]".into());}
    let expected=hash(&args[2])?;
    let color=match args[3].as_str(){"grayscale"=>ComponentInterpretation::Grayscale,"ycbcr"=>ComponentInterpretation::YCbCr,_=>return Err("invalid interpretation".into())};
    let fragment=if args.len()==5{args[4].parse::<usize>()?}else{4096};
    if !(1..=1_048_576).contains(&fragment){return Err("invalid fragment limit".into());}
    let mut wire=Vec::new();std::fs::File::open(&args[1])?.take(64*1024*1024+1).read_to_end(&mut wire)?;
    if wire.len()>64*1024*1024 || ContentDigest::sha256(&wire).bytes()!=expected {return Err("input size or digest mismatch".into());}
    let mut http=HttpResponseStream::new(StreamBasis{source:expected,generation:1},HttpLimits::default())?;
    let mut multipart=None;let mut budget=DecodeBudget::new(4_000_000_000);let mut frames=0;
    for input in wire.chunks(fragment){let mut offset=0;while offset<input.len(){
        let step=http.push(http.next_offset(),&input[offset..],&mut budget)?;
        if step.consumed==0{return Err("HTTP parser made no progress".into());}offset+=step.consumed;
        match step.event {
            Some(HttpEvent::Head(head))=>multipart=Some(HttpMultipartStream::new(&head,MultipartLimits::default(),65536,&mut budget)?),
            Some(HttpEvent::Data(data))=>{let consumer=multipart.as_mut().ok_or("data without header")?;let mut at=0;
                while at<data.bytes().len(){let step=consumer.push(&data,at,&mut budget)?;
                    if step.consumed==0{return Err("MIME parser made no progress".into());}at+=step.consumed;
                    if let Some(frame)=step.frame{emit(&frame,color,&mut budget)?;frames+=1;}}
            },_=>(),
        }
    }}
    let end=http.finish(&mut budget)?;
    let mime=multipart.as_mut().ok_or("missing response")?.finish(end,&mut budget)?;
    if let Some(frame)=mime.final_frame{emit(&frame,color,&mut budget)?;frames+=1;}
    if frames!=mime.multipart.frames{return Err("frame accounting mismatch".into());}
    println!("complete frames={frames} wire_bytes={} entity_bytes={} termination={:?}",end.wire_bytes,end.entity_bytes,end.termination);Ok(())
}
