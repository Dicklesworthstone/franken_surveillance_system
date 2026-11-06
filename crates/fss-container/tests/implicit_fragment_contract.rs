#![forbid(unsafe_code)]
//! Inherited fMP4 addressing, with independent wire fixtures and retained AVC/HEVC media.
//! No decoder or audio implementation is supplied by this contract.

use fss_container::demux::{AvcMp4, DemuxError, DemuxLimits};
use std::error::Error;

type Test<T = ()> = Result<T, Box<dyn Error>>;
const AVC: &[u8] = include_bytes!("fixtures/fragmented_av.mp4");
const HEVC: &[u8] = include_bytes!("fixtures/hevc_fragmented_av.mp4");
const IDR: &[u8] = &[0, 0, 0, 2, 0x65, 0x88];
const PICTURE: &[u8] = &[0, 0, 0, 2, 0x41, 0x9a];

fn word(bytes: &[u8], at: usize) -> Test<u32> {
    Ok(u32::from_be_bytes(bytes.get(at..at + 4).ok_or("fixture word")?.try_into()?))
}
fn put(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_be_bytes());
}
fn words(values: &[u32]) -> Vec<u8> {
    values.iter().flat_map(|n| n.to_be_bytes()).collect()
}
fn atom(kind: &[u8; 4], body: &[u8]) -> Vec<u8> {
    [words(&[(body.len() + 8) as u32]), kind.to_vec(), body.to_vec()].concat()
}
fn full(kind: &[u8; 4], flags: u32, body: &[u8]) -> Vec<u8> {
    atom(kind, &[words(&[flags]), body.to_vec()].concat())
}
fn tags(bytes: &[u8], kind: &[u8; 4]) -> Vec<usize> {
    bytes.windows(4).enumerate().filter_map(|(i, b)| (b == kind).then_some(i)).collect()
}
#[derive(Clone, Copy)]
struct Atom<'a> {
    start: usize,
    kind: [u8; 4],
    bytes: &'a [u8],
    body: &'a [u8],
}
fn atoms(bytes: &[u8]) -> Test<Vec<Atom<'_>>> {
    let mut result = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let len = word(bytes, at)? as usize;
        if len < 8 { return Err("fixture box length".into()); }
        let b = bytes.get(at..at + len).ok_or("fixture box")?;
        result.push(Atom { start: at, kind: b[4..8].try_into()?, bytes: b, body: &b[8..] });
        at += len;
    }
    Ok(result)
}
fn initialization(source: &[u8]) -> Test<Vec<u8>> {
    let first = atoms(source)?.into_iter().find(|a| a.kind == *b"moof").ok_or("fixture moof")?;
    Ok(source[..first.start].to_vec())
}
fn run(flags: u32, count: u32, fields: &[u32]) -> Vec<u8> {
    full(b"trun", flags, &[words(&[count]), words(fields)].concat())
}
fn traf(track: u32, flags: u32, fields: &[u8], runs: &[Vec<u8>]) -> Vec<u8> {
    let mut body = full(b"tfhd", flags, &[words(&[track]), fields.to_vec()].concat());
    for run in runs { body.extend(run); }
    atom(b"traf", &body)
}
fn moof(sequence: u32, tracks: &[Vec<u8>]) -> Vec<u8> {
    let mut body = full(b"mfhd", 0, &words(&[sequence]));
    for track in tracks { body.extend(track); }
    atom(b"moof", &body)
}
// The producer names all offsets directly; it does not implement inherited-address parsing.
fn append_fragment(
    bytes: &mut Vec<u8>, sequence: u32, payload: &[u8],
    tracks: impl Fn(u32, u64) -> Vec<Vec<u8>>,
) -> usize {
    let relative = (moof(sequence, &tracks(0, 0)).len() + 8) as u32;
    let absolute = bytes.len() as u64 + u64::from(relative);
    let fragment = moof(sequence, &tracks(relative, absolute));
    assert_eq!(fragment.len() + 8, relative as usize);
    bytes.extend(fragment);
    bytes.extend(atom(b"mdat", payload));
    absolute as usize
}
fn video(offset: Option<i32>, independent: bool, sizes: &[u32]) -> Vec<u8> {
    let mut fields = Vec::new();
    if let Some(offset) = offset { fields.push(offset as u32); }
    fields.extend_from_slice(sizes);
    traf(1, 0x8 | if independent { 0x20000 } else { 0 }, &words(&[10]),
         &[run(0x200 | u32::from(offset.is_some()), sizes.len() as u32, &fields)])
}
fn basic() -> Test<(Vec<u8>, usize)> {
    let mut bytes = initialization(AVC)?;
    let payload = [vec![0x91; 3], IDR.to_vec(), PICTURE.to_vec()].concat();
    let start = append_fragment(&mut bytes, 1, &payload, |relative, _| vec![
        traf(2, 0x20010, &words(&[1]), &[run(1, 3, &[relative])]),
        video(None, false, &[6, 6]),
    ]);
    Ok((bytes, start))
}
fn parse(bytes: &[u8]) -> Result<AvcMp4<'_>, DemuxError> {
    AvcMp4::parse(bytes, None, DemuxLimits::default())
}
fn refusal(bytes: &[u8]) -> Option<DemuxError> { parse(bytes).err() }

#[test]
fn audio_predecessor_yields_only_exact_video_samples_and_timing() -> Test {
    let (bytes, start) = basic()?;
    let parsed = parse(&bytes)?;
    assert_eq!(parsed.samples().len(), 2);
    assert_eq!(parsed.tracks().len(), 2);
    for (i, payload) in [IDR, PICTURE].iter().enumerate() {
        let sample = &parsed.samples()[i];
        assert_eq!(sample.source, start + 3 + i * 6..start + 9 + i * 6);
        assert_eq!(&bytes[sample.source.clone()], *payload);
        assert_eq!((sample.decode_time, sample.duration), (i as u64 * 10, 10));
    }
    let stream = parsed.annex_b(0, 2)?;
    for mapping in stream.mappings() {
        assert_eq!(&stream.bytes()[mapping.output_start..mapping.output_start + mapping.source.len()],
                   &bytes[mapping.source.clone()]);
        assert!(!mapping.source.contains(&start));
    }
    assert_eq!(AvcMp4::parse_inband(&bytes, None, DemuxLimits::default())?.samples(), parsed.samples());
    Ok(())
}

#[test]
fn each_predecessor_uses_its_own_size_default_with_wire_precedence() -> Test {
    for level in 0..3 {
        let mut bytes = initialization(AVC)?;
        let trex = tags(&bytes, b"trex");
        // Video defaults deliberately differ; borrowing its default would leave the mdat.
        put(&mut bytes, trex[0] + 20, 999);
        put(&mut bytes, trex[1] + 20, if level == 0 { 1 } else { 900 });
        let payload = [vec![0x91; 3], IDR.to_vec()].concat();
        let start = append_fragment(&mut bytes, 1, &payload, |relative, _| {
            let (flags, fields) = if level == 0 { (0x20000, vec![]) }
                else { (0x20010, words(&[if level == 1 { 1 } else { 800 }])) };
            let run = if level == 2 { run(0x201, 3, &[relative, 1, 1, 1]) }
                else { run(1, 3, &[relative]) };
            vec![traf(2, flags, &fields, &[run]), video(None, false, &[6])]
        });
        assert_eq!(parse(&bytes)?.samples()[0].source, start + 3..start + 9);
    }
    Ok(())
}

#[test]
fn multiple_runs_continue_from_their_cursor_and_inherit_the_final_not_largest_end() -> Test {
    for backwards in [false, true] {
        let mut bytes = initialization(AVC)?;
        let payload = if backwards { [vec![0x91], IDR.to_vec(), vec![0x92]].concat() }
            else { [vec![0x91, 0x92], IDR.to_vec()].concat() };
        let start = append_fragment(&mut bytes, 1, &payload, |relative, _| {
            let runs = if backwards {
                vec![run(0x201, 1, &[relative + 7, 1]), run(0x201, 1, &[relative, 1])]
            } else { vec![run(0x201, 1, &[relative, 1]), run(0x200, 1, &[1])] };
            vec![traf(2, 0, &[], &runs), video(None, false, &[6])]
        });
        let offset = if backwards { 1 } else { 2 };
        assert_eq!(parse(&bytes)?.samples()[0].source, start + offset..start + offset + 6);
    }
    Ok(())
}

fn add_third_track(initial: &[u8]) -> Test<Vec<u8>> {
    let mut result = Vec::new();
    for top in atoms(initial)? {
        if top.kind != *b"moov" { result.extend(top.bytes); continue; }
        let children = atoms(top.body)?;
        let source = children.iter().filter(|a| a.kind == *b"trak").nth(1).ok_or("audio track")?;
        let mut track = source.bytes.to_vec();
        let tkhd = tags(&track, b"tkhd")[0];
        put(&mut track, tkhd + 16, 3);
        let mut body = Vec::new();
        for child in children {
            if child.kind != *b"mvex" { body.extend(child.bytes); continue; }
            let defaults = atoms(child.body)?;
            let mut third = defaults.iter().filter(|a| a.kind == *b"trex").nth(1).ok_or("audio trex")?.bytes.to_vec();
            put(&mut third, 12, 3);
            body.extend(atom(b"mvex", &[child.body.to_vec(), third].concat()));
        }
        body.extend(track);
        result.extend(atom(b"moov", &body));
    }
    Ok(result)
}

#[test]
fn implicit_dependency_chains_reset_for_every_movie_fragment() -> Test {
    let mut bytes = add_third_track(&initialization(AVC)?)?;
    let mut expected = Vec::new();
    for sequence in 1..=3 {
        let payload = [vec![0x91; 2], vec![0x92; 3], IDR.to_vec()].concat();
        let start = append_fragment(&mut bytes, sequence, &payload, |relative, _| vec![
            traf(2, 0x10, &words(&[1]), &[run(1, 2, &[relative])]),
            traf(3, 0x10, &words(&[1]), &[run(0, 3, &[])]),
            video(None, false, &[6]),
        ]);
        expected.push(start + 5..start + 11);
    }
    let parsed = parse(&bytes)?;
    assert_eq!(parsed.samples().len(), 3);
    for (i, range) in expected.into_iter().enumerate() {
        assert_eq!(parsed.samples()[i].source, range);
        assert_eq!(parsed.samples()[i].decode_time, i as u64 * 10);
    }
    Ok(())
}

#[test]
fn explicit_base_wins_over_default_moof_and_signed_run_offsets_are_checked() -> Test {
    let mut bytes = initialization(AVC)?;
    let start = append_fragment(&mut bytes, 1, &[vec![0x91], IDR.to_vec()].concat(), |_, absolute| vec![
        traf(2, 0x20011, &[absolute.to_be_bytes().to_vec(), words(&[1])].concat(), &[run(0, 1, &[])]),
        // Explicit base is one byte after the video start; its signed run offset restores it.
        traf(1, 0x20009, &[(absolute + 2).to_be_bytes().to_vec(), words(&[10])].concat(),
             &[run(0x201, 1, &[(-1_i32) as u32, 6])]),
    ]);
    assert_eq!(parse(&bytes)?.samples()[0].source, start + 1..start + 7);
    Ok(())
}
