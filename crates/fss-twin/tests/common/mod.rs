#![forbid(unsafe_code)]
use fss_core::ContentDigest;
use fss_geometry::{GeometryBasis,WorkBudget};
use fss_twin::{ImportExpectation,ImportLimits,PropertyTwin,import_twin};

pub fn twin(levels:&[f64],error:Option<f64>)->Result<PropertyTwin,Box<dyn std::error::Error>> {
    let mut b=vec![1;32];
    for text in ["test/Z-up","synthetic"] {
        b.extend_from_slice(&(text.len() as u16).to_le_bytes());b.extend_from_slice(text.as_bytes());
    }
    b.push(0);
    for n in [0.0f64,-1.0,error.unwrap_or(-1.0)] {b.extend_from_slice(&n.to_le_bytes());}
    for n in [1u32,1,4*levels.len() as u32,2*levels.len() as u32] {b.extend_from_slice(&n.to_le_bytes());}
    b.extend_from_slice(&[4,0]);b.extend_from_slice(b"walk");b.push(1);
    b.extend_from_slice(&[6,0]);b.extend_from_slice(b"ground");b.extend_from_slice(&[0,0,0,0,1,1]);
    for &z in levels {for p in [[0.0,0.0,z],[4.0,0.0,z],[4.0,4.0,z],[0.0,4.0,z]] {
        for n in p {b.extend_from_slice(&n.to_le_bytes());}
    }}
    for i in 0..levels.len() as u32 {for n in [4*i,4*i+1,4*i+2,0,4*i,4*i+2,4*i+3,0] {b.extend_from_slice(&n.to_le_bytes());}}
    let mut bytes=b"FSSTWIN1".to_vec();bytes.extend_from_slice(&(b.len() as u64).to_le_bytes());bytes.extend_from_slice(&b);
    bytes.extend_from_slice(&ContentDigest::sha256(&bytes).bytes());
    Ok(import_twin(&bytes,ImportExpectation{package_sha256:ContentDigest::sha256(&bytes).bytes(),
        source_scene_sha256:[1;32],basis:GeometryBasis::new(1,1)?},ImportLimits::default(),&mut WorkBudget::new(1_000_000))?)
}
