#![forbid(unsafe_code)]
//! Owner-authorized in-memory laboratory. Input is 2 config bytes plus FLV.
use fss_packet::extended_flv::{
    Limits, aac, aac_adts, aac_clock,
    stream::{Framer, Next, SearchMode},
};
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
        return Err("bounded input".into());
    }
    let config = aac::Configuration::parse_explicit(&input[..2])?;
    // Preselected 5 ms tolerance; no retuning if this capture violates it.
    let mut audio_clock = aac_clock::Clock::new(&config, 0, 5, 10_000)?;
    let mut framer = Framer::with_mode(
        Limits::default(),
        8 * 1024 * 1024,
        SearchMode::StructuredTrailer16,
    )?;
    framer.append(0, &input[2..])?;
    let mut output = std::io::stdout().lock();
    let (mut records, mut samples, configs) = (0usize, 0usize, 0usize);
    while let Next::Record(record) = framer.take()? {
        records += 1;
        if records > 10_000 {
            return Err("record limit".into());
        }
        let start = usize::try_from(record.offset())?
            .checked_add(2)
            .ok_or("offset overflow")?;
        let end = start
            .checked_add(record.bytes().len())
            .ok_or("offset overflow")?;
        if input.get(start..end) != Some(record.bytes()) {
            return Err("source custody mismatch".into());
        }
        match aac_adts::source_frame(&config, &record, Limits::default(), aac::Limits::default()) {
            Ok(Some(frame)) => {
                let _timing = audio_clock.observe(frame.timestamp_ms())?;
                let body = frame.body_range();
                let start = usize::try_from(body.start)?
                    .checked_add(2)
                    .ok_or("offset overflow")?;
                let end = usize::try_from(body.end)?
                    .checked_add(2)
                    .ok_or("offset overflow")?;
                if input.get(start..end) != Some(frame.body()) {
                    return Err("audio source range mismatch".into());
                }
                output.write_all(frame.header())?;
                output.write_all(frame.body())?;
                samples += 1;
            }
            Ok(None) => (),
            Err(aac_adts::SourceError::ConfigurationObserved) => {
                return Err("in-stream configuration requires epoch handling".into());
            }
            Err(error) => return Err(error.into()),
        }
    }
    let tail = framer.retire();
    if input.get(
        usize::try_from(tail.offset)?
            .checked_add(2)
            .ok_or("offset overflow")?..,
    ) != Some(tail.bytes())
    {
        return Err("tail mismatch".into());
    }
    if samples == 0 {
        return Err("no audio samples".into());
    }
    output.flush()?;
    eprintln!(
        "samples={samples} configurations={configs} records={records} tail_bytes={} source=caller_supplied authentication=unverified media_saved=no",
        tail.bytes().len()
    );
    Ok(())
}
