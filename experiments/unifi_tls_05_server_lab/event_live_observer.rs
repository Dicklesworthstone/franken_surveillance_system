#![forbid(unsafe_code)]
//! In-memory aggregate check of externally supplied UniFi management frames.
use fss_reference::unifi_direct::events::{self, SmartAudioClaim, SmartAudioField};
use fss_reference::unifi_direct::{
    Controller, Identity, MAX_MESSAGE_BYTES, Observation, events::Kind,
};
use std::io::{self, Read};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut controller = Controller::new(
        Identity::new("FSS", "12345678-1234-4abc-9abc-123456789abc", "1.20.0")?,
        1,
    )?;
    let mut input = io::stdin().lock();
    let mut seen = 0usize;
    let mut parsed = 0usize;
    let mut other = 0usize;
    let mut smart_audio = 0usize;
    let mut expected = 0usize;
    let mut rejected = 0usize;
    let mut structured_audio = 0usize;
    let mut unsupported_fields = 0usize;
    let mut unknown_fields = 0usize;
    let mut audio_refused = 0usize;
    let audio_fields = [
        SmartAudioField::ClockMonotonic,
        SmartAudioField::ClockStream,
        SmartAudioField::ClockStreamRate,
        SmartAudioField::ClockWall,
        SmartAudioField::EventId,
        SmartAudioField::LevelDb,
        SmartAudioField::Levels,
        SmartAudioField::AlarmBabyCry,
        SmartAudioField::AlarmBark,
        SmartAudioField::AlarmBurglar,
        SmartAudioField::AlarmCarHorn,
        SmartAudioField::AlarmCmonx,
        SmartAudioField::AlarmGlassBreak,
        SmartAudioField::AlarmSiren,
        SmartAudioField::AlarmSmoke,
        SmartAudioField::AlarmSpeak,
        SmartAudioField::LoudNoise,
        SmartAudioField::SoundLoss,
    ];
    loop {
        let mut header = [0_u8; 4];
        match input.read_exact(&mut header) {
            Ok(()) => (),
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }
        let len = u32::from_be_bytes(header) as usize;
        if len == 0 || len > MAX_MESSAGE_BYTES || seen >= 32 {
            return Err("input bound".into());
        }
        let mut bytes = vec![0_u8; len];
        input.read_exact(&mut bytes)?;
        seen += 1;
        match controller.observe_event_claims(&bytes) {
            Ok(Observation::CameraEvent {
                kind,
                response_expected,
                ..
            }) => {
                parsed += 1;
                if kind == Kind::Other {
                    other += 1;
                }
                if kind == Kind::SmartAudio {
                    smart_audio += 1;
                    match events::interpret_smart_audio_source(&bytes) {
                        Ok(audio) => {
                            structured_audio += 1;
                            unknown_fields += audio.unknown_fields();
                            unsupported_fields += audio_fields
                                .iter()
                                .filter(|field| {
                                    matches!(audio.get(**field), SmartAudioClaim::Unsupported)
                                })
                                .count();
                        }
                        Err(_) => audio_refused += 1,
                    }
                }
                if response_expected {
                    expected += 1;
                }
            }
            _ => rejected += 1,
        }
        bytes.fill(0);
    }
    println!(
        "input_frames={seen} parsed_events={parsed} smart_audio_events={smart_audio} structured_audio={structured_audio} unsupported_fields={unsupported_fields} unknown_fields={unknown_fields} audio_refused={audio_refused} other_events={other} response_expected={expected} rejected={rejected}"
    );
    Ok(())
}
