#![forbid(unsafe_code)]
//! Local read-only interchange inspection; not an fss/1 authority operation.
use std::{fs::File, io::Read};
use fss_geometry::{GeometryBasis, WorkBudget};
use fss_twin::{ImportExpectation, ImportLimits, import_twin};

fn digest(text: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err("digest must contain 64 lowercase hexadecimal characters".into());
    }
    let mut bytes=[0;32];
    for (out, pair) in bytes.iter_mut().zip(text.as_bytes().as_chunks::<2>().0) {
        let nibble=|b:u8| if b<=b'9' { b-b'0' } else { b-b'a'+10 };
        *out=nibble(pair[0])*16+nibble(pair[1]);
    }
    Ok(bytes)
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_>=std::env::args_os().skip(1).collect();
    if args.len()!=3 { return Err("usage: import_twin FILE PACKAGE_SHA256 SOURCE_SCENE_SHA256".into()); }
    let expected=ImportExpectation {
        package_sha256:digest(args[1].to_str().ok_or("invalid digest text")?)?,
        source_scene_sha256:digest(args[2].to_str().ok_or("invalid digest text")?)?,
        basis:GeometryBasis::new(1,1)?,
    };
    let mut bytes=Vec::new();
    File::open(&args[0])?.take(64*1024*1024+1).read_to_end(&mut bytes)?;
    let mut budget=WorkBudget::new(150_000_000);
    let twin=import_twin(&bytes,expected,ImportLimits::default(),&mut budget)?;
    println!("{{\"status\":\"imported_unactivated\",\"features\":{},\"objects\":{},\"triangles\":{},\"work_units\":{}}}",
        twin.features().len(),twin.objects().len(),twin.triangles().len(),budget.used());
    Ok(())
}
