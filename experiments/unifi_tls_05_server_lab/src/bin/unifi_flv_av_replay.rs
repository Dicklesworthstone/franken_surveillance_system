#![forbid(unsafe_code)]
//! Explicitly authorized laboratory: input is two AAC config bytes plus FLV.
//! Writes one sensitive MP4 to stdout; caller must capture it privately in
//! memory. This does not authenticate a camera or qualify continuous recording.

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

fn main() -> Result<(), Box<dyn Error>> {
    let mut input = Vec::new();
    std::io::stdin()
        .lock()
        .take(8 * 1024 * 1024 + 3)
        .read_to_end(&mut input)?;
    if input.len() < 15 || input.len() > 8 * 1024 * 1024 + 2 || !input[2..].starts_with(b"FLV\x01")
    {
        return Err("invalid bounded input".into());
    }
    let config = aac::Configuration::parse_explicit(&input[..2])?;
    if config.sample_rate() != 16_000 || config.channels() != 1 {
        return Err("unsupported laboratory profile".into());
    }
    let mut framer = Framer::with_mode(
        FlvLimits::default(),
        8 * 1024 * 1024,
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
    let mut records = 0usize;
    while let Next::Record(record) = framer.take()? {
        records += 1;
        if records > 10_000 {
            return Err("record limit".into());
        }
        let start = usize::try_from(record.offset())?
            .checked_add(2)
            .ok_or("source offset")?;
        let end = start
            .checked_add(record.bytes().len())
            .ok_or("source offset")?;
        if input.get(start..end) != Some(record.bytes()) {
            return Err("source mismatch".into());
        }
        match recorder.push(record).map_err(|refusal| refusal.reason)? {
            Push::Source { .. } | Push::Buffered => (),
            Push::Segment(segment) => {
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
                let mut clock = aac_clock::Clock::new(&config, start_ticks, 5, 4096)?;
                let mut audio = Vec::new();
                for frame in &frames {
                    audio.push(TimedAudio {
                        frame,
                        time: clock.observe(frame.timestamp_ms())?,
                    });
                }
                let init = recorder
                    .av_initialization(&config)?
                    .ok_or("missing A/V initialization")?;
                let av = flv_av::fragment(&init, video, &config, &audio, Mp4Limits::default())?;
                let mut stdout = std::io::stdout().lock();
                stdout.write_all(init.bytes())?;
                stdout.write_all(av.bytes())?;
                stdout.flush()?;
                eprintln!(
                    "segments=1 video_samples={} audio_samples={} first_audio_video_delta_ms={} configuration=caller_supplied alignment=sender_clock_assumption",
                    video.samples().len(),
                    audio.len(),
                    delta
                );
                return Ok(());
            }
        }
    }
    Err("no complete A/V segment".into())
}
