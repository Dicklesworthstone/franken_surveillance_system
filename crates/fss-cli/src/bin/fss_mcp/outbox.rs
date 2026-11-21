#![forbid(unsafe_code)]
//! Bounded response allocation and serialized delivery for the MCP controller.
//! Identity remains owned through the final newline. The owner supplies enqueue times
//! and output admission checks; production delivery samples no ambient clock here.

use std::{
    collections::VecDeque,
    io::{self, Write},
    time::Instant,
};

struct Pending<K> {
    response: String,
    key: Option<K>,
    offset: usize,
    charge: usize,
    enqueued: Instant,
}

pub(super) struct Outbox<K: Eq> {
    frames: VecDeque<Pending<K>>,
    allocated_bytes: usize,
    max_bytes: usize,
    max_frames: usize,
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct Progress<K> {
    pub written: usize,
    pub completed: usize,
    pub retired: Vec<K>,
    pub oldest_written: Option<Instant>,
}

impl<K> Default for Progress<K> {
    fn default() -> Self {
        Self {
            written: 0,
            completed: 0,
            retired: Vec::new(),
            oldest_written: None,
        }
    }
}

const MAX_WRITE_ATTEMPTS: usize = 64;

impl<K: Eq> Outbox<K> {
    pub fn new(max_bytes: usize, max_frames: usize) -> Self {
        Self {
            frames: VecDeque::new(),
            allocated_bytes: 0,
            max_bytes,
            max_frames,
        }
    }

    /// Check additional reservations without releasing memory for bytes already
    /// written from a still-owned frame. Identity/index overhead is separately
    /// bounded by the frame ceiling and admitted request-ID limits.
    pub fn capacity_for(&self, bytes: usize, frames: usize) -> bool {
        self.allocated_bytes
            .checked_add(bytes)
            .is_some_and(|total| total <= self.max_bytes)
            && self
                .frames
                .len()
                .checked_add(frames)
                .is_some_and(|total| total <= self.max_frames)
    }

    #[cfg(test)]
    pub fn enqueue(&mut self, response: String, key: Option<K>) -> io::Result<()> {
        self.enqueue_at(response, key, Instant::now())
    }

    pub fn enqueue_at(
        &mut self,
        response: String,
        key: Option<K>,
        enqueued: Instant,
    ) -> io::Result<()> {
        // Keep the string unchanged and write its LF separately. Appending LF
        // could grow an exact-capacity string before checking the memory bound.
        let charge = response.capacity().checked_add(1).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "MCP output size overflow")
        })?;
        if !self.capacity_for(charge, 1) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "MCP output queue is at its byte or frame ceiling",
            ));
        }
        self.allocated_bytes += charge;
        self.frames.push_back(Pending {
            response,
            key,
            offset: 0,
            charge,
            enqueued,
        });
        Ok(())
    }

    /// Advance at most `max_bytes` and 64 write attempts, including interrupts.
    /// A key retires only after its complete frame and LF have been accepted.
    /// A permanent write error is terminal for the transport: earlier frames
    /// may already have been delivered, so callers must not replay the queue.
    #[cfg(test)]
    pub fn progress(
        &mut self,
        output: &mut impl Write,
        max_bytes: usize,
    ) -> io::Result<Progress<K>> {
        self.progress_checked(output, max_bytes, |_| Ok(()))
    }

    /// Revalidate the owning response's original delivery budget before every
    /// write, including its final LF and retry after interruption. Partial output
    /// never replaces its enqueue time with a newer one.
    pub fn progress_checked(
        &mut self,
        output: &mut impl Write,
        max_bytes: usize,
        mut admit: impl FnMut(Instant) -> io::Result<()>,
    ) -> io::Result<Progress<K>> {
        let mut progress = Progress::default();
        for _ in 0..MAX_WRITE_ATTEMPTS {
            if progress.written >= max_bytes {
                break;
            }
            let Some(frame) = self.frames.front_mut() else {
                break;
            };
            admit(frame.enqueued)?;
            let remaining = max_bytes - progress.written;
            let bytes = if frame.offset < frame.response.len() {
                let bytes = &frame.response.as_bytes()[frame.offset..];
                &bytes[..bytes.len().min(remaining)]
            } else {
                b"\n"
            };
            match output.write(bytes) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "MCP output accepted no bytes",
                    ));
                }
                Ok(written) if written > bytes.len() => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "MCP writer reported an invalid byte count",
                    ));
                }
                Ok(written) => {
                    progress.oldest_written = Some(
                        progress
                            .oldest_written
                            .map_or(frame.enqueued, |previous| previous.min(frame.enqueued)),
                    );
                    frame.offset += written;
                    progress.written += written;
                    if frame.offset > frame.response.len() {
                        let frame = self
                            .frames
                            .pop_front()
                            .ok_or_else(|| io::Error::other("MCP owned output frame missing"))?;
                        self.allocated_bytes -= frame.charge;
                        progress.completed += 1;
                        if let Some(key) = frame.key {
                            progress.retired.push(key);
                        }
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error),
            }
        }
        Ok(progress)
    }

    pub fn oldest_enqueued(&self) -> Option<Instant> {
        self.frames.front().map(|frame| frame.enqueued)
    }

    /// An identity stays owned until its complete frame and newline retire.
    pub fn owns(&self, key: &K) -> bool {
        self.frames
            .iter()
            .any(|frame| frame.key.as_ref() == Some(key))
    }

    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    pub fn clear(&mut self) {
        self.frames.clear();
        self.allocated_bytes = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn error_kind<T>(result: io::Result<T>) -> io::Result<io::ErrorKind> {
        match result {
            Err(error) => Ok(error.kind()),
            Ok(_) => Err(io::Error::other("expected an I/O refusal")),
        }
    }

    struct Sink {
        bytes: Vec<u8>,
        allowance: usize,
        chunk: usize,
        interrupts: usize,
        calls: usize,
    }

    impl Sink {
        fn new(allowance: usize, chunk: usize) -> Self {
            Self {
                bytes: Vec::new(),
                allowance,
                chunk,
                interrupts: 0,
                calls: 0,
            }
        }
    }

    impl Write for Sink {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.calls += 1;
            if self.interrupts > 0 {
                self.interrupts -= 1;
                return Err(io::ErrorKind::Interrupted.into());
            }
            if self.allowance == 0 {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            let written = bytes.len().min(self.allowance).min(self.chunk);
            self.bytes.extend_from_slice(&bytes[..written]);
            self.allowance -= written;
            Ok(written)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn partial_frames_keep_identity_until_complete_ordered_delivery() -> io::Result<()> {
        let first = 1_i64;
        let second = 2_i64;
        let mut outbox = Outbox::<i64>::new(1024, 4);
        outbox.enqueue(r#"{"id":1,"result":"é"}"#.into(), Some(first))?;
        outbox.enqueue(r#"{"id":2}"#.into(), Some(second))?;
        let mut sink = Sink::new(3, 2);
        let progress = outbox.progress(&mut sink, 100)?;
        assert_eq!(progress.written, 3);
        assert_eq!(progress.completed, 0);
        assert!(progress.retired.is_empty());
        assert!(outbox.owns(&first));
        assert!(outbox.owns(&second));
        outbox.enqueue(r#"{"id":null}"#.into(), None)?;
        sink.allowance = 1024;
        let progress = outbox.progress(&mut sink, 1024)?;
        assert_eq!(progress.completed, 3);
        assert_eq!(progress.retired, [first, second]);
        assert_eq!(
            sink.bytes,
            "{\"id\":1,\"result\":\"é\"}\n{\"id\":2}\n{\"id\":null}\n".as_bytes(),
        );
        assert!(outbox.is_empty());
        Ok(())
    }

    #[test]
    fn allocated_capacity_stays_charged_until_the_newline_retires() -> io::Result<()> {
        let mut response = String::with_capacity(128);
        response.push('x');
        let charge = response.capacity() + 1;
        let key = 3_i64;
        let mut outbox = Outbox::<i64>::new(charge, 1);
        outbox.enqueue(response, Some(key))?;
        assert!(!outbox.capacity_for(1, 0));
        assert!(!outbox.capacity_for(0, 1));
        assert!(!outbox.capacity_for(usize::MAX, 1));
        assert!(outbox.enqueue(String::new(), None).is_err());
        let mut sink = Sink::new(1024, 1024);
        let progress = outbox.progress(&mut sink, 1)?;
        assert_eq!(progress.written, 1);
        assert!(progress.retired.is_empty());
        assert!(!outbox.capacity_for(1, 0));
        assert!(outbox.owns(&key));
        assert_eq!(outbox.progress(&mut sink, 1)?.retired, [key]);
        assert!(!outbox.owns(&key));
        assert!(outbox.capacity_for(charge, 1));
        assert_eq!(sink.bytes, b"x\n");
        let mut oversized = String::with_capacity(charge);
        oversized.push('x');
        assert!(outbox.enqueue(oversized, None).is_err());
        outbox.enqueue("ok".into(), None)?;
        outbox.clear();
        assert!(outbox.is_empty());
        assert!(outbox.capacity_for(charge, 1));
        Ok(())
    }

    #[test]
    fn every_poll_bounds_interrupts_successful_writes_and_bytes() -> io::Result<()> {
        let mut outbox = Outbox::<i64>::new(1024, 1);
        outbox.enqueue("x".repeat(256), None)?;
        let mut sink = Sink::new(1024, 1);
        sink.interrupts = usize::MAX;
        assert_eq!(outbox.progress(&mut sink, 1024)?, Progress::default());
        assert_eq!(sink.calls, MAX_WRITE_ATTEMPTS);
        sink.interrupts = 0;
        sink.calls = 0;
        assert_eq!(
            outbox.progress(&mut sink, 1024)?.written,
            MAX_WRITE_ATTEMPTS
        );
        assert_eq!(sink.calls, MAX_WRITE_ATTEMPTS);
        sink.calls = 0;
        assert_eq!(outbox.progress(&mut sink, 3)?.written, 3);
        assert_eq!(sink.calls, 3);
        assert_eq!(outbox.progress(&mut sink, 0)?, Progress::default());
        assert_eq!(sink.calls, 3);
        Ok(())
    }

    #[test]
    fn zero_write_is_a_terminal_error_without_claiming_a_delivered_response() -> io::Result<()> {
        let key = 9_i64;
        let mut outbox = Outbox::<i64>::new(128, 1);
        outbox.enqueue("{}".into(), Some(key))?;
        let mut sink = Sink::new(128, 0);
        assert_eq!(
            error_kind(outbox.progress(&mut sink, 128))?,
            io::ErrorKind::WriteZero
        );
        assert!(sink.bytes.is_empty());
        assert!(outbox.owns(&key));
        outbox.clear();
        assert!(outbox.is_empty());
        assert!(!outbox.owns(&key));
        Ok(())
    }

    #[test]
    fn deadline_is_rechecked_before_the_final_newline() -> io::Result<()> {
        use std::cell::Cell;
        use std::time::Duration;

        let admitted = Instant::now();
        let deadline = admitted + Duration::from_millis(5);
        let now = Cell::new(admitted);
        let mut outbox = Outbox::new(128, 2);
        outbox.enqueue_at("body".into(), Some(1_u8), admitted)?;
        let mut sink = Sink::new(128, 128);
        let result = outbox.progress_checked(&mut sink, 128, |enqueued| {
            assert_eq!(enqueued, admitted);
            if now.get() >= deadline {
                return Err(io::ErrorKind::TimedOut.into());
            }
            // The first admitted write can finish; the next write is already out of time.
            now.set(deadline);
            Ok(())
        });
        assert_eq!(error_kind(result)?, io::ErrorKind::TimedOut);
        assert_eq!(sink.bytes, b"body");
        assert_eq!(sink.calls, 1);
        assert!(outbox.owns(&1));
        assert_eq!(outbox.oldest_enqueued(), Some(admitted));
        outbox.enqueue_at("later".into(), Some(2), now.get())?;
        let calls = sink.calls;
        assert_eq!(
            error_kind(
                outbox
                    .progress_checked(&mut sink, 128, |_| { Err(io::ErrorKind::TimedOut.into()) })
            )?,
            io::ErrorKind::TimedOut
        );
        assert_eq!(sink.calls, calls);
        assert!(outbox.owns(&1) && outbox.owns(&2));
        Ok(())
    }

    #[test]
    fn retired_bytes_keep_the_original_flush_time_and_successor_keeps_its_age() -> io::Result<()> {
        use std::time::Duration;

        let first_time = Instant::now();
        let second_time = first_time + Duration::from_millis(1);
        let mut outbox = Outbox::new(128, 2);
        outbox.enqueue_at("one".into(), Some(1_u8), first_time)?;
        outbox.enqueue_at("two".into(), Some(2), second_time)?;
        let mut sink = Sink::new(128, 128);
        let progress = outbox.progress_checked(&mut sink, 4, |_| Ok(()))?;
        assert_eq!(progress.retired, [1]);
        assert_eq!(progress.oldest_written, Some(first_time));
        assert_eq!(outbox.oldest_enqueued(), Some(second_time));
        assert_eq!(sink.bytes, b"one\n");
        let now = second_time + Duration::from_millis(5);
        let calls = sink.calls;
        let result = outbox.progress_checked(&mut sink, 128, |enqueued| {
            if now.duration_since(enqueued) >= Duration::from_millis(5) {
                Err(io::ErrorKind::TimedOut.into())
            } else {
                Ok(())
            }
        });
        assert_eq!(error_kind(result)?, io::ErrorKind::TimedOut);
        assert_eq!(sink.calls, calls);
        assert!(outbox.owns(&2));
        Ok(())
    }

    #[test]
    fn interrupted_writes_recheck_the_same_delivery_deadline() -> io::Result<()> {
        use std::cell::Cell;
        use std::time::Duration;

        let admitted = Instant::now();
        let elapsed = Cell::new(0_u64);
        let mut outbox = Outbox::new(128, 1);
        outbox.enqueue_at("response".into(), Some(1_u8), admitted)?;
        let mut sink = Sink::new(128, 128);
        sink.interrupts = usize::MAX;
        let result = outbox.progress_checked(&mut sink, 128, |enqueued| {
            let now = admitted + Duration::from_millis(elapsed.get());
            if now.duration_since(enqueued) >= Duration::from_millis(3) {
                return Err(io::ErrorKind::TimedOut.into());
            }
            elapsed.set(elapsed.get() + 1);
            Ok(())
        });
        assert_eq!(error_kind(result)?, io::ErrorKind::TimedOut);
        assert_eq!(sink.calls, 3);
        assert!(sink.bytes.is_empty());
        assert!(outbox.owns(&1));
        assert_eq!(outbox.oldest_enqueued(), Some(admitted));
        Ok(())
    }
}
