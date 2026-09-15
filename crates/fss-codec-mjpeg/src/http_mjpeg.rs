#![forbid(unsafe_code)]
//! HTTP entity events -> multipart frames with exact JPEG-to-wire span maps.
//! Original HTTP events stay borrowed and caller-owned, including on failure.

use crate::{ComponentInterpretation,DecodeBudget,DecodeError,DecodeLimits,DecodedLuma};
use crate::http::{EntityData,HttpEnd,HttpHeadIdentity,ResponseHead};
use crate::multipart::{MultipartEnd,MultipartError,MultipartFrame,MultipartLimits,MultipartRemainder,MultipartStream};

/// Bounded composition failures, never partial image/whole-response success.
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub enum HttpMjpegError {
    /// A different response, skipped data, stale end or bad offset was supplied.
    BasisMismatch,
    /// Source mapping or allocation bound was exceeded; no top-k map is returned.
    Limit,
    /// Multipart bytes or configuration were refused.
    Multipart(MultipartError),
    /// Caller computation/cancellation allowance failed.
    Work(DecodeError),
    /// An earlier error latched; abort or create a new owner generation.
    Poisoned,
    /// Entity already completed.
    Closed,
}
impl From<DecodeError> for HttpMjpegError {fn from(e:DecodeError)->Self{Self::Work(e)}}
impl From<MultipartError> for HttpMjpegError {fn from(e:MultipartError)->Self{Self::Multipart(e)}}
impl std::fmt::Display for HttpMjpegError {
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {
        f.write_str(match self {Self::BasisMismatch=>"HTTP/multipart source mismatch",Self::Limit=>"HTTP/multipart map limit",
            Self::Multipart(_)=>"HTTP/multipart input refused",Self::Work(_)=>"HTTP/multipart work interrupted",
            Self::Poisoned=>"HTTP/multipart has a prior failure",Self::Closed=>"HTTP/multipart closed"})
    }
}
impl std::error::Error for HttpMjpegError {}
/// Accepted prefix on error. The caller still owns the complete original HTTP event.
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct HttpMjpegFailure {
    /// This failure; first terminal reason is retained by the consumer.
    pub error:HttpMjpegError,
    /// Entity bytes accepted from this call's data suffix.
    pub consumed:usize,
    /// Next absolute dechunked-entity offset.
    pub next_entity_offset:u64,
}
impl std::fmt::Display for HttpMjpegFailure {
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {std::fmt::Display::fmt(&self.error,f)}
}
impl std::error::Error for HttpMjpegFailure {}
/// Direct source mapping. JPEG ranges are relative to the frame's first SOI byte.
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct JpegWireSpan {
    /// Half-open original plaintext HTTP response byte range.
    pub wire_range:[u64;2],
    /// Half-open corresponding offset range within this JPEG payload only.
    pub jpeg_range:[u64;2],
    /// Original nonzero chunk ordinal, or None for identity transfer.
    pub chunk:Option<u64>,
}
/// A complete MIME-delimited frame with a complete source map, not decoded pixels.
#[derive(Debug)]
pub struct HttpJpegFrame {head:HttpHeadIdentity,part:MultipartFrame,spans:Vec<JpegWireSpan>}
impl HttpJpegFrame {
    /// Exact HTTP response/entity basis, without copying private header text.
    pub fn head(&self)->HttpHeadIdentity {self.head}
    /// Existing multipart payload and its headers/ranges; compatible with twin ingestion.
    pub fn part(&self)->&MultipartFrame {&self.part}
    /// Complete JPEG byte coverage in order, excluding all HTTP and MIME overhead.
    pub fn source_spans(&self)->&[JpegWireSpan] {&self.spans}
    /// Decode all entropy using the same first-party baseline JPEG decoder.
    pub fn decode(&self,interpretation:ComponentInterpretation,limits:DecodeLimits,budget:&mut DecodeBudget<'_>)
        ->Result<DecodedLuma,DecodeError> {self.part.decode(interpretation,limits,budget)}
}
/// Consumer progress; a large HTTP data record can contain several MIME parts.
#[derive(Debug)]
pub struct HttpMjpegStep {
    /// Consumed prefix of the borrowed data suffix. Call again for its remainder.
    pub consumed:usize,
    /// At most one source-mapped frame, after its following delimiter was checked.
    pub frame:Option<HttpJpegFrame>,
}
/// Successful transfer AND MIME termination. A close-delimited HTTP EOF stays labeled.
#[derive(Debug)]
pub struct HttpMjpegEnd {
    /// Upstream HTTP termination receipt, not replaced by MIME success.
    pub http:HttpEnd,
    /// Exact multipart wrapper/part accounting.
    pub multipart:MultipartEnd,
    /// Final part when MIME's final delimiter completed only at entity EOF.
    pub final_frame:Option<HttpJpegFrame>,
}
/// Direct dechunked-entity to wire run, also retained for abort reconciliation.
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct EntityWireRun {
    /// Original plaintext-response range.
    pub wire_range:[u64;2],
    /// Corresponding unchanged entity range.
    pub entity_range:[u64;2],
    /// Chunk ordinal when transfer coding splits otherwise adjacent entity bytes.
    pub chunk:Option<u64>,
}
/// Source recovery after any failure. Original HTTP records always remain caller-owned.
#[derive(Debug)]
pub struct HttpMjpegRemainder {
    /// Exact response binding.
    pub head:HttpHeadIdentity,
    /// First terminal consumer error, or None for an explicit owner abort.
    pub reason:Option<HttpMjpegError>,
    /// Multipart parser's unexposed bytes and source ranges.
    pub multipart:MultipartRemainder,
    /// A completed part retained when source-map publication failed.
    pub pending_frame:Option<MultipartFrame>,
    /// MIME completion retained when final source-map publication failed.
    pub pending_end:Option<MultipartEnd>,
    /// Retained runs since the last published frame; not a full-session custody log.
    pub runs:Vec<EntityWireRun>,
}
/// Single-owner consumer of validated HTTP data events. No network or output callbacks.
/// The caller retains the original head/control/data events and explicitly supplies
/// the HTTP end receipt. It is never inferred from a JPEG or MIME end marker.
pub struct HttpMultipartStream {
    head:HttpHeadIdentity, multipart:MultipartStream, runs:Vec<EntityWireRun>, maximum_runs:usize,
    last_wire_end:u64, failure:Option<HttpMjpegError>, closed:bool,
    pending_frame:Option<MultipartFrame>,pending_end:Option<MultipartEnd>,
}
impl std::fmt::Debug for HttpMultipartStream {
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {
        f.debug_struct("HttpMultipartStream").field("entity_offset",&self.next_entity_offset())
            .field("failure",&self.failure).finish_non_exhaustive()
    }
}
impl HttpMultipartStream {
    /// Use the admitted response Content-Type, not a separately guessed boundary.
    /// Runs coalesce only when both byte domains are contiguous in the same chunk.
    pub fn new(head:&ResponseHead,limits:MultipartLimits,maximum_runs:usize,budget:&mut DecodeBudget<'_>)
        ->Result<Self,HttpMjpegError> {
        if !(1..=65536).contains(&maximum_runs) {return Err(HttpMjpegError::Limit);}
        let multipart=MultipartStream::new(head.identity().entity,head.content_type(),limits,budget)?;
        Ok(Self{head:head.identity(),multipart,runs:Vec::new(),maximum_runs,last_wire_end:head.raw().range()[1],
            failure:None,closed:false,pending_frame:None,pending_end:None})
    }
    /// Exact next expected dechunked-entity offset.
    pub fn next_entity_offset(&self)->u64 {self.multipart.next_offset()}
    /// First terminal error, without source byte disclosure.
    pub fn failure(&self)->Option<HttpMjpegError> {self.failure}
    /// Consume a suffix of one actual HTTP Data event. Retain and reuse that record
    /// when a frame boundary causes this call to stop before its end.
    pub fn push(&mut self,data:&EntityData,start:usize,budget:&mut DecodeBudget<'_>)
        ->Result<HttpMjpegStep,HttpMjpegFailure> {
        let mut consumed=0;
        let result=(||{
            self.active(budget)?;
            let map=data.mapping();
            if map.head!=self.head || start>data.bytes().len()
                || map.entity_range[0]+start as u64!=self.multipart.next_offset()
                || map.wire_range[0]+(start as u64)<self.last_wire_end {return Err(HttpMjpegError::BasisMismatch);}
            if start==data.bytes().len() {return Ok(None);}
            let entity_start=map.entity_range[0]+start as u64;
            let wire_start=map.wire_range[0]+start as u64;
            let join=self.runs.last().is_some_and(|r|r.wire_range[1]==wire_start
                && r.entity_range[1]==entity_start && r.chunk==map.chunk);
            if !join {
                if self.runs.len()==self.maximum_runs {return Err(HttpMjpegError::Limit);}
                self.runs.try_reserve(1).map_err(|_|HttpMjpegError::Limit)?;
            }
            budget.charge(32)?;
            let step=self.multipart.push(entity_start,&data.bytes()[start..],budget);
            consumed=match &step {Ok(s)=>s.consumed,Err(e)=>e.consumed};
            if consumed!=0 {
                let wire_end=wire_start+consumed as u64;let entity_end=entity_start+consumed as u64;
                if join {if let Some(last)=self.runs.last_mut() {last.wire_range[1]=wire_end;last.entity_range[1]=entity_end;}}
                else {self.runs.push(EntityWireRun{wire_range:[wire_start,wire_end],entity_range:[entity_start,entity_end],chunk:map.chunk});}
                self.last_wire_end=wire_end;
            }
            let step=step.map_err(|e|HttpMjpegError::Multipart(e.error))?;
            self.pending_frame=step.frame;
            self.publish_frame(budget)
        })();
        match result {Ok(frame)=>Ok(HttpMjpegStep{consumed,frame}),Err(error)=>{
            if self.failure.is_none(){self.failure=Some(error);}
            Err(HttpMjpegFailure{error,consumed,next_entity_offset:self.multipart.next_offset()})}}
    }
    fn active(&self,budget:&mut DecodeBudget<'_>)->Result<(),HttpMjpegError> {
        budget.charge(0)?;
        if self.failure.is_some(){return Err(HttpMjpegError::Poisoned);}
        if self.closed{return Err(HttpMjpegError::Closed);}Ok(())
    }
    fn publish_frame(&mut self,budget:&mut DecodeBudget<'_>)->Result<Option<HttpJpegFrame>,HttpMjpegError> {
        let Some(part)=self.pending_frame.as_ref() else {return Ok(None);};
        let receipt=part.receipt();let [begin,end]=receipt.jpeg_range;
        let mut covered=begin;let mut spans=Vec::new();
        budget.charge(self.runs.len() as u64*4+1)?;
        spans.try_reserve_exact(self.runs.len()).map_err(|_|HttpMjpegError::Limit)?;
        for run in &self.runs {
            let lo=run.entity_range[0].max(begin);let hi=run.entity_range[1].min(end);
            if lo>=hi {continue;}
            if lo!=covered {return Err(HttpMjpegError::BasisMismatch);}
            let wire=run.wire_range[0]+lo-run.entity_range[0];
            spans.push(JpegWireSpan{wire_range:[wire,wire+hi-lo],jpeg_range:[lo-begin,hi-begin],chunk:run.chunk});covered=hi;
        }
        if covered!=end || spans.is_empty() {return Err(HttpMjpegError::BasisMismatch);}
        budget.charge(0)?;
        let Some(part)=self.pending_frame.take() else {return Err(HttpMjpegError::BasisMismatch);};
        // The preceding/next MIME delimiter is shared. Its maps can also support
        // abort reconciliation, while older HTTP data remains with the owner.
        self.runs.retain(|r|r.entity_range[1]>receipt.closing_range[0]);
        Ok(Some(HttpJpegFrame{head:self.head,part,spans}))
    }
    /// Complete only after upstream HTTP termination AND downstream MIME closure.
    /// A public receipt is an owner input, not an authentication or custody token.
    pub fn finish(&mut self,end:HttpEnd,budget:&mut DecodeBudget<'_>)->Result<HttpMjpegEnd,HttpMjpegError> {
        let result=(||{
            self.active(budget)?;
            if end.head!=self.head || end.entity_bytes!=self.multipart.next_offset() || end.wire_bytes<self.last_wire_end {
                return Err(HttpMjpegError::BasisMismatch);
            }
            let finish=self.multipart.finish(budget).map_err(|e|HttpMjpegError::Multipart(e.error))?;
            self.pending_frame=finish.frame;self.pending_end=Some(finish.end);
            let final_frame=self.publish_frame(budget)?;
            // No fallible work follows removal of retained final-frame ownership.
            let multipart=self.pending_end.take().ok_or(HttpMjpegError::BasisMismatch)?;
            self.closed=true;
            Ok(HttpMjpegEnd{http:end,multipart,final_frame})
        })();
        if let Err(error)=&result {if self.failure.is_none(){self.failure=Some(*error);}}
        result
    }
    /// Recover unexposed source parts and maps without allocating or polling work.
    pub fn abort(self)->HttpMjpegRemainder {HttpMjpegRemainder{head:self.head,reason:self.failure,
        multipart:self.multipart.abort(),pending_frame:self.pending_frame,pending_end:self.pending_end,runs:self.runs}}
}
