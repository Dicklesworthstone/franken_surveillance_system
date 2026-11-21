"use client";
import { useSyncExternalStore } from "react";

/** One clock for the whole console. Time is in seconds from the start of the take. */
export function createClock(duration, fps) {
  let time = 0;
  let playing = false;
  let last = 0;
  let raf = 0;
  const listeners = new Set();
  const emit = () => listeners.forEach((fn) => fn());
  const step = (now) => {
    // A hidden tab stops animation frames. On return the clock carries on from about where it was.
    time += Math.min((now - last) / 1000, 1);
    last = now;
    if (time >= duration) {
      time = duration;
      playing = false;
    }
    emit();
    if (playing) raf = requestAnimationFrame(step);
  };
  return {
    duration,
    fps,
    time: () => time,
    frame: () => Math.min(Math.round(duration * fps) - 1, Math.floor(time * fps + 1e-6)),
    playing: () => playing,
    subscribe(fn) {
      listeners.add(fn);
      return () => listeners.delete(fn);
    },
    play() {
      if (playing) return;
      if (time >= duration - 0.05) time = 0;
      playing = true;
      last = performance.now();
      raf = requestAnimationFrame(step);
      emit();
    },
    pause() {
      if (!playing) return;
      playing = false;
      cancelAnimationFrame(raf);
      emit();
    },
    seek(t) {
      time = Math.max(0, Math.min(duration, t));
      emit();
    },
    stop() {
      playing = false;
      cancelAnimationFrame(raf);
      listeners.clear();
    },
  };
}

/** Re-renders at the film's frame rate, not the display's. */
export const useFrame = (clock) =>
  useSyncExternalStore(clock.subscribe, clock.frame, () => 0);
export const usePlaying = (clock) =>
  useSyncExternalStore(clock.subscribe, clock.playing, () => false);
