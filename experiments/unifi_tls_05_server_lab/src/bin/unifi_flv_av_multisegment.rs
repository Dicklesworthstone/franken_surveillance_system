#![forbid(unsafe_code)]
//! Explicitly authorized laboratory: input is two AAC config bytes plus FLV.
//! Writes sensitive MP4 bytes to stdout only after a bounded complete replay.
//! The caller must capture them privately in memory. This experiment does not
//! authenticate a camera, save media, or qualify continuous recording.

use fss_container::{
    Mp4Limits,
    flv_av::{self, TimedAudio},
    flv_avc::SourceKey,
};
use fss_packet::extended_flv::{
    Limits as FlvLimits, aac, aac_adts, aac_clock,
    stream::{Framer, Next, SearchMode},
};
use fss_reference::unifi_direct::recording::{self, Push, Recorder};
use std::{
    error::Error,
    io::{Read, Write},
};

const MAX_INPUT: usize = 8 * 1024 * 1024;
const MAX_OUTPUT: usize = 16 * 1024 * 1024;

fn append(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    if output
        .len()
        .checked_add(bytes.len())
        .is_none_or(|n| n > MAX_OUTPUT)
    {
        return Err("output limit".into());
    }
    output.try_reserve_exact(bytes.len())?;
    output.extend_from_slice(bytes);
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut input = Vec::new();
    std::io::stdin()
        .lock()
        .take((MAX_INPUT + 3) as u64)
        .read_to_end(&mut input)?;
    if input.len() < 15 || input.len() > MAX_INPUT + 2 || !input[2..].starts_with(b"FLV\x01") {
        return Err("invalid bounded input".into());
    }
    let config = aac::Configuration::parse_explicit(&input[..2])?;
    if config.sample_rate() != 16_000 || config.channels() != 1 {
        return Err("unsupported laboratory profile".into());
    }
    let mut framer = Framer::with_mode(
        FlvLimits::default(),
        MAX_INPUT,
        SearchMode::StructuredTrailer16,
    )?;
    framer.append(0, &input[2..])?;
    let mut recorder = Recorder::new(
        SourceKey {
            connection: 1,
            generation: 1,
        },
        recording::Limits::default(),
    )?;
    let mut init = None;
    let mut av_session = None;
    let mut clock = None;
    let mut movie = Vec::new();
    let (mut offset, mut records, mut segments, mut video_samples, mut audio_samples) =
        (0usize, 0usize, 0usize, 0usize, 0usize);
    let mut initial_delta = None;
    while let Next::Record(record) = framer.take()? {
        records += 1;
        if records > 10_000 || record.offset() != offset as u64 {
            return Err("source order".into());
        }
        let end = offset
            .checked_add(record.bytes().len())
            .ok_or("source offset")?;
        if input.get(offset + 2..end + 2) != Some(record.bytes()) {
            return Err("source mismatch".into());
        }
        offset = end;
        match recorder.push(record).map_err(|refusal| refusal.reason)? {
            Push::Source { .. } | Push::Buffered => (),
            Push::Segment(segment) => {
                if segments >= 16 {
                    return Err("segment limit".into());
                }
                let video = segment.fragment();
                let video_start = video
                    .samples()
                    .first()
                    .ok_or("missing video")?
                    .decode_time_ms;
                let mut frames = Vec::new();
                for source in segment.source() {
                    if let Some(frame) = aac_adts::source_frame(
                        &config,
                        source,
                        FlvLimits::default(),
                        aac::Limits::default(),
                    )? {
                        if frames.len() >= 4096 {
                            return Err("audio sample limit".into());
                        }
                        let span = frame.body_range();
                        let start = usize::try_from(span.start)?
                            .checked_add(2)
                            .ok_or("audio offset")?;
                        let end = usize::try_from(span.end)?
                            .checked_add(2)
                            .ok_or("audio offset")?;
                        if input.get(start..end) != Some(frame.body()) {
                            return Err("audio source mismatch".into());
                        }
                        frames.push(frame);
                    }
                }
                if clock.is_none() {
                    let first = frames.first().ok_or("missing audio")?.timestamp_ms();
                    let delta = i64::from(first.wrapping_sub(video_start as u32) as i32);
                    if delta.unsigned_abs() > 2_000 {
                        return Err("audio video timestamp separation".into());
                    }
                    let audio_ms = video_start
                        .checked_add_signed(delta)
                        .ok_or("audio timestamp")?;
                    let start_ticks = audio_ms
                        .checked_mul(u64::from(config.sample_rate()))
                        .ok_or("clock overflow")?
                        / 1000;
                    clock = Some(aac_clock::Clock::new(&config, start_ticks, 5, 4096)?);
                    initial_delta = Some(delta);
                }
                if frames.is_empty() {
                    return Err("missing segment audio".into());
                }
                if init.is_none() {
                    let value = recorder
                        .av_initialization(&config)?
                        .ok_or("missing A/V initialization")?;
                    av_session = Some(flv_av::Session::new(&value)?);
                    append(&mut movie, value.bytes())?;
                    init = Some(value);
                }
                let mut audio = Vec::new();
                audio.try_reserve_exact(frames.len())?;
                for frame in &frames {
                    audio.push(TimedAudio {
                        frame,
                        time: clock
                            .as_mut()
                            .ok_or("missing clock")?
                            .observe(frame.timestamp_ms())?,
                    });
                }
                let av = av_session.as_mut().ok_or("missing A/V session")?.fragment(
                    init.as_ref().ok_or("missing init")?,
                    video,
                    &config,
                    &audio,
                    Mp4Limits::default(),
                )?;
                append(&mut movie, av.bytes())?;
                segments += 1;
                video_samples = video_samples
                    .checked_add(video.samples().len())
                    .ok_or("sample count")?;
                audio_samples = audio_samples
                    .checked_add(audio.len())
                    .ok_or("sample count")?;
            }
        }
    }
    let tail = framer.retire();
    if tail.offset != offset as u64 || input.get(offset + 2..) != Some(tail.bytes()) {
        return Err("tail mismatch".into());
    }
    let remaining = recorder.retire();
    if segments < 2 {
        return Err("fewer than two complete segments".into());
    }
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(&movie)?;
    stdout.flush()?;
    eprintln!(
        "segments={segments} video_samples={video_samples} audio_samples={audio_samples} first_audio_video_delta_ms={} tail_bytes={} pending_records={} configuration=caller_supplied alignment=sender_clock_assumption",
        initial_delta.ok_or("missing delta")?,
        tail.bytes().len(),
        remaining.pending.len()
    );
    Ok(())
}
