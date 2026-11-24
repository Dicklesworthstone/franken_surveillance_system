#![forbid(unsafe_code)]
//! Deterministic RIFF wrapping of the existing generated color-bar JPEG fixture.

/// Existing independently decodable 64-by-48 JPEG.
pub const JPEG: &[u8] =
    include_bytes!("../../../../tests/fixtures/media/jpeg/rgb_64x48_colorbars_420.jpg");

fn chunk(kind: &[u8; 4], body: &[u8]) -> Vec<u8> {
    let mut bytes = kind.to_vec();
    bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
    bytes.extend_from_slice(body);
    if !body.len().is_multiple_of(2) {
        bytes.push(0x7f);
    }
    bytes
}

fn list(kind: &[u8; 4], contents: &[u8]) -> Vec<u8> {
    let mut bytes = kind.to_vec();
    bytes.extend_from_slice(contents);
    chunk(b"LIST", &bytes)
}

fn set(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

/// Three MJPEG frames at 30000/1001 fps plus twelve opaque PCM samples.
/// Stream ordering and the optional record lists vary while JPEG bytes remain exact.
pub fn movie(audio_first: bool, records: bool) -> Vec<u8> {
    movie_with_frames(&[JPEG, JPEG, JPEG], audio_first, records)
}

/// Build the same framing around owner-supplied JPEG chunks for refusal contracts.
pub fn movie_with_frames(frames: &[&[u8]], audio_first: bool, records: bool) -> Vec<u8> {
    let mut main = [0_u8; 56];
    set(&mut main, 0, 33_367);
    set(&mut main, 16, frames.len() as u32);
    set(&mut main, 24, 2);
    set(&mut main, 32, 64);
    set(&mut main, 36, 48);
    let mut video = [0_u8; 56];
    video[..8].copy_from_slice(b"vidsMJPG");
    set(&mut video, 20, 1001);
    set(&mut video, 24, 30_000);
    set(&mut video, 28, 7);
    set(&mut video, 32, frames.len() as u32);
    video[52..54].copy_from_slice(&64_u16.to_le_bytes());
    video[54..56].copy_from_slice(&48_u16.to_le_bytes());
    let mut bitmap = [0_u8; 40];
    set(&mut bitmap, 0, 40);
    set(&mut bitmap, 4, 64);
    set(&mut bitmap, 8, 48);
    bitmap[12..16].copy_from_slice(&[1, 0, 24, 0]);
    bitmap[16..20].copy_from_slice(b"MJPG");
    let mut properties = [0_u8; 68];
    for (offset, value) in [
        (8, 30), (12, 64), (16, 48), (20, (4 << 16) | 3),
        (24, 64), (28, 48), (32, 1), (36, 48), (40, 64),
        (44, 48), (48, 64),
    ] {
        set(&mut properties, offset, value);
    }
    let video = list(
        b"strl",
        &[
            chunk(b"strh", &video),
            chunk(b"strf", &bitmap),
            chunk(b"vprp", &properties),
        ].concat(),
    );

    let mut audio = [0_u8; 56];
    audio[..4].copy_from_slice(b"auds");
    set(&mut audio, 20, 1);
    set(&mut audio, 24, 8000);
    set(&mut audio, 32, frames.len() as u32 * 4);
    set(&mut audio, 44, 2);
    let mut wave = [0_u8; 18];
    wave[..4].copy_from_slice(&[1, 0, 1, 0]);
    set(&mut wave, 4, 8000);
    set(&mut wave, 8, 16_000);
    wave[12..16].copy_from_slice(&[2, 0, 16, 0]);
    let audio = list(b"strl", &[chunk(b"strh", &audio), chunk(b"strf", &wave)].concat());
    let streams = if audio_first { [audio, video] } else { [video, audio] };
    let headers = list(b"hdrl", &[chunk(b"avih", &main), streams.concat()].concat());
    let (video_tag, audio_tag) = if audio_first {
        (b"01dc", b"00wb")
    } else {
        (b"00dc", b"01wb")
    };
    let mut data = Vec::new();
    for frame in frames {
        let record = [
            chunk(video_tag, frame),
            chunk(audio_tag, &[0, 1, 0, 2, 0, 3, 0, 4]),
            chunk(b"JUNK", b"odd"),
        ]
        .concat();
        if records {
            data.extend_from_slice(&list(b"rec ", &record));
        } else {
            data.extend_from_slice(&record);
        }
    }
    let body = [
        b"AVI ".to_vec(),
        headers,
        chunk(b"JUNK", b"opaque capture metadata"),
        list(b"movi", &data),
    ]
    .concat();
    chunk(b"RIFF", &body)
}
