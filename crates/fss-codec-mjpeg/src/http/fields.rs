#![forbid(unsafe_code)]
use super::{BodyFraming,HttpError};
use std::ops::Range;

fn token(b:u8)->bool {b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)}
fn trim(bytes:&[u8],mut range:Range<usize>)->Range<usize> {
    while range.start<range.end && b" \t".contains(&bytes[range.start]) {range.start+=1;}
    while range.start<range.end && b" \t".contains(&bytes[range.end-1]) {range.end-=1;}
    range
}
fn field_ranges(bytes:&[u8],start:usize)->Result<Vec<(Range<usize>,Range<usize>)>,HttpError> {
    let mut fields=Vec::new();let mut offset=start;
    while offset<bytes.len() {
        let n=bytes[offset..].windows(2).position(|w|w==b"\r\n").ok_or(HttpError::Malformed)?;
        if n==0 {return if offset+2==bytes.len() {Ok(fields)} else {Err(HttpError::Malformed)};}
        if n>4094 || fields.len()==64 {return Err(HttpError::Limit);}
        let line=&bytes[offset..offset+n];
        let colon=line.iter().position(|b|*b==b':').ok_or(HttpError::Malformed)?;
        if colon==0 || !line[..colon].iter().all(|b|token(*b))
            || line[colon+1..].iter().any(|b|(*b<32 && *b!=9)||*b==127) {return Err(HttpError::Malformed);}
        fields.try_reserve(1).map_err(|_|HttpError::Limit)?;
        fields.push((offset..offset+colon,trim(bytes,offset+colon+1..offset+n)));offset+=n+2;
    }
    Err(HttpError::Malformed)
}
fn once<T>(slot:&mut Option<T>,value:T)->Result<(),HttpError> {
    if slot.is_some(){return Err(HttpError::Malformed);}*slot=Some(value);Ok(())
}
pub(super) fn head(bytes:&[u8])->Result<(BodyFraming,Range<usize>),HttpError> {
    let end=bytes.windows(2).position(|w|w==b"\r\n").ok_or(HttpError::Malformed)?;
    let line=&bytes[..end];
    if line.len()<13 || line[8]!=b' ' || line[12]!=b' '
        || !line[9..12].iter().all(u8::is_ascii_digit)
        || line[13..].iter().any(|b|(*b<32 && *b!=9)||*b==127) {return Err(HttpError::Malformed);}
    if &line[..8]!=b"HTTP/1.1" && &line[..8]!=b"HTTP/1.0" {return Err(HttpError::Unsupported);}
    let status=u16::from(line[9]-b'0')*100+u16::from(line[10]-b'0')*10+u16::from(line[11]-b'0');
    if status!=200 {return Err(HttpError::Status(status));}
    let mut length=None;let mut transfer=None;let mut content=None;let mut encoding=None;
    for (name,value) in field_ranges(bytes,end+2)? {
        let key=&bytes[name];let v=&bytes[value.clone()];
        if key.eq_ignore_ascii_case(b"content-length") {
            if v.is_empty() || !v.iter().all(u8::is_ascii_digit) {return Err(HttpError::Malformed);}
            let mut n=0_u64;for b in v {n=n.checked_mul(10).and_then(|n|n.checked_add(u64::from(*b-b'0'))).ok_or(HttpError::Limit)?;}
            once(&mut length,n)?;
        } else if key.eq_ignore_ascii_case(b"transfer-encoding") {
            if !v.eq_ignore_ascii_case(b"chunked") {return Err(HttpError::Unsupported);}once(&mut transfer,())?;
        } else if key.eq_ignore_ascii_case(b"content-type") {
            if v.is_empty() || !v.is_ascii() {return Err(HttpError::Malformed);}once(&mut content,value)?;
        } else if key.eq_ignore_ascii_case(b"content-encoding") {
            if !v.eq_ignore_ascii_case(b"identity") {return Err(HttpError::Unsupported);}once(&mut encoding,())?;
        } else if key.eq_ignore_ascii_case(b"connection") || key.eq_ignore_ascii_case(b"trailer") {
            for part in v.split(|b|*b==b',') {
                let part=&part[trim(part,0..part.len())];
                if part.is_empty() || !part.iter().all(|b|token(*b)) {return Err(HttpError::Malformed);}
                if forbidden_trailer(part) {return Err(HttpError::Malformed);}
            }
        }
    }
    if transfer.is_some() && (length.is_some() || &line[..8]==b"HTTP/1.0") {return Err(HttpError::Malformed);}
    Ok((if transfer.is_some(){BodyFraming::Chunked}else if let Some(n)=length{BodyFraming::Length(n)}else{BodyFraming::UntilEof},
        content.ok_or(HttpError::Unsupported)?))
}
fn forbidden_trailer(name:&[u8])->bool {
    [b"content-length".as_slice(),b"transfer-encoding",b"content-type",b"content-encoding",b"content-range",b"host",
        b"trailer",b"connection",b"authorization",b"proxy-authorization",b"www-authenticate",b"proxy-authenticate",
        b"cookie",b"set-cookie",b"location",b"content-location",b"cache-control"].iter().any(|key|name.eq_ignore_ascii_case(key))
}
pub(super) fn trailers(bytes:&[u8])->Result<(),HttpError> {
    let fields=field_ranges(bytes,0)?;
    for (i,(name,_)) in fields.iter().enumerate() {
        if forbidden_trailer(&bytes[name.clone()]) || fields[..i].iter().any(|(other,_)|
            bytes[name.clone()].eq_ignore_ascii_case(&bytes[other.clone()])) {return Err(HttpError::Malformed);}
    }
    Ok(())
}
pub(super) fn chunk_size(bytes:&[u8])->Result<u64,HttpError> {
    let line=bytes.strip_suffix(b"\r\n").ok_or(HttpError::Malformed)?;
    let mut i=0;let mut value=0_u64;
    while i<line.len() && line[i].is_ascii_hexdigit() {
        let d=match line[i] {b'0'..=b'9'=>line[i]-b'0',b'a'..=b'f'=>line[i]-b'a'+10,b=>b-b'A'+10};
        value=value.checked_mul(16).and_then(|n|n.checked_add(u64::from(d))).ok_or(HttpError::Limit)?;i+=1;
        if i>16 {return Err(HttpError::Limit);}
    }
    if i==0 {return Err(HttpError::Malformed);}
    while i<line.len() {
        skip_ows(line,&mut i);
        if line.get(i)!=Some(&b';') {return Err(HttpError::Malformed);}i+=1;skip_ows(line,&mut i);
        let start=i;while i<line.len() && token(line[i]) {i+=1;}
        if i==start {return Err(HttpError::Malformed);}
        let end=i;skip_ows(line,&mut i);
        if line.get(i)!=Some(&b'=') {
            if i==line.len() && i!=end {return Err(HttpError::Malformed);}
            continue;
        }
        i+=1;skip_ows(line,&mut i);
        if line.get(i)==Some(&b'"') {
            i+=1;let mut closed=false;
            while i<line.len() {
                let b=line[i];i+=1;
                if b==b'"' {closed=true;break;}
                if b==b'\\' {
                    let b=*line.get(i).ok_or(HttpError::Malformed)?;i+=1;
                    if b!=9 && !(32..=126).contains(&b) && b<128 {return Err(HttpError::Malformed);}
                } else if b!=9 && b!=32 && b!=33 && !(35..=91).contains(&b) && !(93..=126).contains(&b) && b<128 {
                    return Err(HttpError::Malformed);
                }
            }
            if !closed {return Err(HttpError::Malformed);}
        } else {
            let start=i;while i<line.len() && token(line[i]) {i+=1;}
            if start==i {return Err(HttpError::Malformed);}
        }
    }
    Ok(value)
}
fn skip_ows(line:&[u8],i:&mut usize) {while *i<line.len() && b" \t".contains(&line[*i]) {*i+=1;}}
