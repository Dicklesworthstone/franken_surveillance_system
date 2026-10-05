#![forbid(unsafe_code)]
//! Independent sample-table fixtures plus a retained FFmpeg laboratory encoding.
use super::*;

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
fn atom(kind: &[u8; 4], body: &[u8]) -> Vec<u8> {
    let mut bytes = ((body.len() + 8) as u32).to_be_bytes().to_vec();
    bytes.extend_from_slice(kind); bytes.extend_from_slice(body); bytes
}
fn full_atom(kind: &[u8; 4], version: u8, flags: u32, body: &[u8]) -> Vec<u8> {
    let mut b = ((u32::from(version) << 24) | flags).to_be_bytes().to_vec();
    b.extend_from_slice(body); atom(kind, &b)
}
fn words(values: &[u32]) -> Vec<u8> { values.iter().flat_map(|v| v.to_be_bytes()).collect() }
fn table(kind: &[u8; 4], values: &[u32], width: usize) -> Vec<u8> {
    let mut b = ((values.len() / width) as u32).to_be_bytes().to_vec();
    b.extend(words(values)); full_atom(kind, 0, 0, &b)
}
#[derive(Clone, Copy, Default)]
struct Options { length: usize, co64: bool, signed_ctts: bool, second_track: bool, duplicate_sizes: bool }
struct Fixture { bytes: Vec<u8>, sources: Vec<Range<usize>>, payloads: Vec<Vec<u8>> }
fn fixture(options: Options, sizes: &[usize]) -> Fixture {
    let length = if options.length == 0 { 4 } else { options.length };
    let ftyp = atom(b"ftyp", b"isom\0\0\0\0isomavc1");
    let mut payload = Vec::new(); let mut sources = Vec::new(); let mut payloads = Vec::new();
    for (i, size) in sizes.iter().enumerate() {
        let mut nal = vec![(i as u8).wrapping_add(50); *size];
        nal[0] = if i == 0 { 0x65 } else { 0x41 };
        let start = ftyp.len() + 8 + payload.len();
        let prefix = (nal.len() as u32).to_be_bytes(); payload.extend_from_slice(&prefix[4 - length..]);
        payload.extend_from_slice(&nal); sources.push(start..start + length + nal.len()); payloads.push(nal);
    }
    let mdat = atom(b"mdat", &payload);
    let mut visual = vec![0_u8; 78];
    visual[6..8].copy_from_slice(&1_u16.to_be_bytes());
    visual[24..26].copy_from_slice(&64_u16.to_be_bytes()); visual[26..28].copy_from_slice(&48_u16.to_be_bytes());
    let mut avcc = vec![1, 66, 0, 30, 0xfc | (length as u8 - 1), 0xe1, 0, 4, 0x67, 66, 0, 30, 1, 0, 2, 0x68, 0x80];
    visual.extend(atom(b"avcC", &avcc)); avcc.clear();
    let mut stsd = words(&[1]); stsd.extend(atom(b"avc1", &visual));
    let mut stbl = full_atom(b"stsd", 0, 0, &stsd);
    stbl.extend(table(b"stts", &[sizes.len() as u32, 10], 2));
    let mut ctts = words(&[sizes.len() as u32]);
    for i in 0..sizes.len() {
        ctts.extend(words(&[1, if i == 0 && options.signed_ctts { (-5_i32) as u32 } else { i as u32 }]));
    }
    stbl.extend(full_atom(b"ctts", u8::from(options.signed_ctts), 0, &ctts));
    stbl.extend(table(b"stss", &[1], 1));
    // One chunk per sample tests the table join independently of sample byte scanning.
    stbl.extend(table(b"stsc", &[1, 1, 1], 3));
    let mut stsz = words(&[0, sizes.len() as u32]);
    stsz.extend(words(&sizes.iter().map(|n| (length + n) as u32).collect::<Vec<_>>()));
    let size_atom = full_atom(b"stsz", 0, 0, &stsz); stbl.extend(&size_atom);
    if options.duplicate_sizes { stbl.extend(size_atom); }
    if options.co64 {
        let mut positions = words(&[sources.len() as u32]);
        for source in &sources { positions.extend_from_slice(&(source.start as u64).to_be_bytes()); }
        stbl.extend(full_atom(b"co64", 0, 0, &positions));
    } else { stbl.extend(table(b"stco", &sources.iter().map(|r| r.start as u32).collect::<Vec<_>>(), 1)); }
    let mut dref = words(&[1]); dref.extend(full_atom(b"url ", 0, 1, &[]));
    let mut minf = atom(b"dinf", &full_atom(b"dref", 0, 0, &dref)); minf.extend(atom(b"stbl", &stbl));
    let mut mdhd = words(&[0, 0, 100, sizes.len() as u32 * 10]); mdhd.extend_from_slice(&[0; 4]);
    let mut hdlr = words(&[0]); hdlr.extend_from_slice(b"vide"); hdlr.extend_from_slice(&[0; 12]);
    let mut mdia = full_atom(b"mdhd", 0, 0, &mdhd); mdia.extend(full_atom(b"hdlr", 0, 0, &hdlr)); mdia.extend(atom(b"minf", &minf));
    let track = |id: u32| {
        let mut tkhd = vec![0; 84]; tkhd[3] = 3; tkhd[12..16].copy_from_slice(&id.to_be_bytes());
        for (i, n) in [0x10000_u32, 0, 0, 0, 0x10000, 0, 0, 0, 0x40000000].iter().enumerate() {
            tkhd[40 + i * 4..44 + i * 4].copy_from_slice(&n.to_be_bytes());
        }
        let mut trak = atom(b"tkhd", &tkhd); trak.extend(atom(b"mdia", &mdia)); atom(b"trak", &trak)
    };
    let mut mvhd = vec![0; 100]; mvhd[12..16].copy_from_slice(&1000_u32.to_be_bytes());
    let mut moov = atom(b"mvhd", &mvhd); moov.extend(track(1)); if options.second_track { moov.extend(track(2)); }
    let mut bytes = ftyp; bytes.extend(mdat); bytes.extend(atom(b"moov", &moov));
    Fixture { bytes, sources, payloads }
}
fn field(bytes: &[u8], kind: &[u8; 4], offset_from_body: usize) -> usize {
    bytes.windows(4).position(|p| p == kind).expect("fixture box") + 4 + offset_from_body
}
fn patch32(bytes: &mut [u8], at: usize, value: u32) { bytes[at..at + 4].copy_from_slice(&value.to_be_bytes()); }

#[test]
fn sample_tables_produce_exact_byte_and_timeline_maps() -> Test {
    for length in [1, 2, 4] { for co64 in [false, true] {
        let f = fixture(Options { length, co64, signed_ctts: true, ..Options::default() }, &[5, 7, 9, 11]);
        let parsed = AvcMp4::parse(&f.bytes, None, DemuxLimits::default())?;
        assert_eq!(parsed.track_id(), 1); assert_eq!(parsed.timescale(), 100); assert_eq!(parsed.dimensions(), [64, 48]);
        for (i, sample) in parsed.samples().iter().enumerate() {
            assert_eq!(sample.source, f.sources[i]); assert_eq!(sample.decode_time, i as u64 * 10);
            assert_eq!(sample.duration, 10); assert_eq!(sample.sync_sample, i == 0);
        }
        assert_eq!(parsed.samples()[0].presentation_time(), -5);
        let stream = parsed.annex_b(0, 4)?;
        assert_eq!(stream.selection(), [0, 4]); assert_eq!(stream.mappings().len(), 6);
        for map in stream.mappings() {
            assert_eq!(&stream.bytes()[map.output_start - 4..map.output_start], &[0, 0, 0, 1]);
            assert_eq!(&stream.bytes()[map.output_start..map.output_start + map.source.len()], &f.bytes[map.source.clone()]);
            if let Some(sample) = map.sample { assert_eq!(&f.bytes[map.source.clone()], &f.payloads[sample]); }
        }
    }}
    Ok(())
}
#[test]
fn unselected_tracks_require_explicit_unambiguous_selection() -> Test {
    let f = fixture(Options { second_track: true, ..Options::default() }, &[3, 6]);
    assert!(matches!(AvcMp4::parse(&f.bytes, None, DemuxLimits::default()), Err(DemuxError::TrackSelection)));
    let p = AvcMp4::parse(&f.bytes, Some(2), DemuxLimits::default())?;
    assert_eq!(p.track_id(), 2); assert_eq!(p.tracks().len(), 2);
    assert!(matches!(AvcMp4::parse(&f.bytes, Some(3), DemuxLimits::default()), Err(DemuxError::TrackSelection)));
    Ok(())
}
#[test]
fn every_truncated_prefix_is_refused_without_panicking() {
    let f = fixture(Options::default(), &[3, 6]);
    for end in 0..f.bytes.len() { assert!(AvcMp4::parse(&f.bytes[..end], None, DemuxLimits::default()).is_err(), "prefix {end}"); }
}
#[test]
fn duplicate_singleton_offsets_outside_mdat_and_overlaps_are_refused() {
    let f = fixture(Options { duplicate_sizes: true, ..Options::default() }, &[3, 6]);
    assert!(matches!(AvcMp4::parse(&f.bytes, None, DemuxLimits::default()), Err(DemuxError::DuplicateBox(_))));
    for value in [0, 24 + 8] {
        let mut f = fixture(Options::default(), &[3, 6]);
        let at = field(&f.bytes, b"stco", 12); patch32(&mut f.bytes, at, value);
        assert!(AvcMp4::parse(&f.bytes, None, DemuxLimits::default()).is_err());
    }
}
#[test]
fn incompatible_encryption_and_external_data_are_never_fetched() {
    let mut f = fixture(Options::default(), &[3, 6]);
    let at = field(&f.bytes, b"url ", 0); patch32(&mut f.bytes, at, 0);
    assert!(matches!(AvcMp4::parse(&f.bytes, None, DemuxLimits::default()), Err(DemuxError::Unsupported)));
    let mut f = fixture(Options::default(), &[3, 6]);
    let at = f.bytes.windows(4).rposition(|p| p == b"avc1").expect("entry"); f.bytes[at..at + 4].copy_from_slice(b"encv");
    assert!(matches!(AvcMp4::parse(&f.bytes, None, DemuxLimits::default()), Err(DemuxError::Unsupported)));
}
#[test]
fn invalid_counts_and_changed_parameter_sets_refuse_complete_parse() {
    for (kind, offset, value) in [(b"stts", 8, 3), (b"stsc", 16, 2), (b"stss", 8, 99), (b"stsz", 8, u32::MAX)] {
        let mut f = fixture(Options::default(), &[4, 6]); let at = field(&f.bytes, kind, offset); patch32(&mut f.bytes, at, value);
        assert!(AvcMp4::parse(&f.bytes, None, DemuxLimits::default()).is_err(), "{kind:?}");
    }
    let mut f = fixture(Options::default(), &[4, 6]); f.bytes[f.sources[1].start + 4] = 0x67;
    assert!(matches!(AvcMp4::parse(&f.bytes, None, DemuxLimits::default()), Err(DemuxError::Nal)));
}
#[test]
fn zero_nals_false_sync_and_non_random_access_extractions_are_refused() -> Test {
    let mut f = fixture(Options::default(), &[4, 6]); let at = f.sources[0].start; patch32(&mut f.bytes, at, 0);
    assert!(matches!(AvcMp4::parse(&f.bytes, None, DemuxLimits::default()), Err(DemuxError::Nal)));
    let mut f = fixture(Options::default(), &[4, 6]); f.bytes[f.sources[0].start + 4] = 0x41;
    let parsed = AvcMp4::parse(&f.bytes, None, DemuxLimits::default())?;
    assert!(matches!(parsed.annex_b(0, 2), Err(DemuxError::RandomAccessRequired)));
    let f = fixture(Options::default(), &[4, 6]); let parsed = AvcMp4::parse(&f.bytes, None, DemuxLimits::default())?;
    assert!(matches!(parsed.annex_b(1, 1), Err(DemuxError::RandomAccessRequired)));
    assert!(parsed.annex_b(0, 0).is_err()); assert!(parsed.annex_b(usize::MAX, 2).is_err()); Ok(())
}
#[test]
fn independent_limits_and_cancellation_refuse_without_mutating_selection() -> Test {
    let f = fixture(Options::default(), &[4, 6]);
    let limits = DemuxLimits::default();
    for narrow in [DemuxLimits { maximum_input_bytes: f.bytes.len() - 1, ..limits },
        DemuxLimits { maximum_samples: 1, ..limits }, DemuxLimits { maximum_nals: 1, ..limits },
        DemuxLimits { maximum_boxes: 1, ..limits }, DemuxLimits { maximum_table_entries: 1, ..limits }] {
        assert!(matches!(AvcMp4::parse(&f.bytes, None, narrow), Err(DemuxError::Limit)));
    }
    assert!(matches!(AvcMp4::parse_with_checkpoint(&f.bytes, None, limits, &mut || Err(DemuxError::Cancelled)), Err(DemuxError::Cancelled)));
    let parsed = AvcMp4::parse(&f.bytes, None, DemuxLimits { maximum_output_bytes: 1, ..limits })?;
    assert!(matches!(parsed.annex_b(0, 2), Err(DemuxError::Limit)));
    let parsed = AvcMp4::parse(&f.bytes, None, limits)?; let before = parsed.samples().to_vec();
    let mut visits = 0;
    assert!(matches!(parsed.annex_b_with_checkpoint(0, 2, &mut || { visits += 1; if visits == 4 { Err(DemuxError::Cancelled) } else { Ok(()) } }), Err(DemuxError::Cancelled)));
    assert_eq!(parsed.samples(), before.as_slice()); assert!(parsed.annex_b(0, 2).is_ok()); Ok(())
}
#[test]
fn unsigned_composition_offsets_are_not_reinterpreted_as_signed() -> Test {
    let mut f = fixture(Options::default(), &[4, 6]); let at = field(&f.bytes, b"ctts", 12); patch32(&mut f.bytes, at, u32::MAX);
    let parsed = AvcMp4::parse(&f.bytes, None, DemuxLimits::default())?;
    assert_eq!(parsed.samples()[0].presentation_time(), i128::from(u32::MAX)); Ok(())
}
#[test]
fn many_variable_sample_layouts_match_the_independent_construction() -> Test {
    let mut seed = 115_u64;
    for count in 1..=64 {
        let sizes: Vec<usize> = (0..count).map(|_| { seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1); 2 + ((seed >> 32) as usize % 120) }).collect();
        let f = fixture(Options { co64: count % 2 == 0, ..Options::default() }, &sizes);
        let p = AvcMp4::parse(&f.bytes, None, DemuxLimits::default())?;
        assert_eq!(p.samples().iter().map(|s| s.source.clone()).collect::<Vec<_>>(), f.sources);
        let result = p.annex_b(0, count)?;
        assert_eq!(result.mappings().len(), count + 2);
    }
    Ok(())
}
#[test]
fn actual_lab_mp4_preserves_b_frame_timing_edits_and_all_nal_payloads() -> Test {
    let bytes = include_bytes!("../../tests/fixtures/indexed_avc.mp4");
    let p = AvcMp4::parse(bytes, None, DemuxLimits::default())?;
    assert_eq!(p.timescale(), 10240); assert_eq!(p.dimensions(), [64, 48]); assert_eq!(p.samples().len(), 10);
    assert_eq!(p.edits().len(), 1); assert_eq!(p.edits()[0].media_time, 4096);
    let positions = [967, 2707, 2783, 2832, 2865, 2946, 4109, 4208, 4229, 4287];
    let presentation = [0, 6144, 2048, 4096, 8192, 10240, 12288, 16384, 14336, 18432];
    for (i, sample) in p.samples().iter().enumerate() {
        assert_eq!(sample.source.start, positions[i]);
        assert_eq!(sample.presentation_time() - 4096, presentation[i]);
        assert_eq!(sample.decode_time, i as u64 * 2048);
    }
    for (first, count) in [(0, 10), (5, 5)] {
        let out = p.annex_b(first, count)?;
        for copy in out.mappings() { assert_eq!(&out.bytes()[copy.output_start..copy.output_start + copy.source.len()], &bytes[copy.source.clone()]); }
    }
    Ok(())
}
