"use strict";
(() => {
  const video = document.getElementById("player");
  const status = document.getElementById("status");
  const token = location.hash.slice(1);
  history.replaceState(null, "", "/");
  if (!/^[0-9a-f]{32}$/.test(token)) {
    status.textContent = "Open the private viewer link printed by the running capture.";
    return;
  }
  const MediaSourceType = window.MediaSource;
  if (!MediaSourceType) {
    status.textContent = "This browser does not support Media Source Extensions. Preview playback is unavailable.";
    return;
  }
  // The owner starts playback explicitly. Native autoplay on a replacement source must
  // not undo a user's pause after a decoder error or source-buffer reset.
  video.autoplay = false;
  const controller = new AbortController();
  const headers = {"X-FSS-Read": "1", "X-FSS-Preview": token};
  const POLL_MS = 500, MEDIA_WAIT_MS = 4000, REQUEST_MS = 6000, MAX_FAILURES = 3;
  let stopped = false, polling = false, timer = null, failures = 0, mediaFailures = 0;
  let sequence = null, installed = null, current = null, clock = null;
  let media = null, buffer = null, mime = null, sourceUrl = null, mediaAbort = null;
  let origin = 0, previousStart = null, generation = 0, failedGeneration = -1;
  let mediaFailed = false, playing = false, userPaused = false, playBlocked = false, playAttempt = null;
  let skipped = 0, unavailable = 0;
  const delivery = document.getElementById("delivery");
  const showDelivery = () => {
    delivery.textContent = skipped + " preview windows skipped; " + unavailable +
      " requested windows expired before delivery. These are viewer omissions, not a recording-loss assessment.";
  };
  const interrupted = () => new DOMException("Playback was interrupted.", "AbortError");
  function bounded(work, signal, milliseconds, message, cancel = () => {}) {
    return new Promise((resolve, reject) => {
      let settled = false, deadline;
      const finish = (fn, value) => {
        if (settled) return;
        settled = true; clearTimeout(deadline); signal.removeEventListener("abort", abort); fn(value);
      };
      const abort = () => { cancel(); finish(reject, interrupted()); };
      deadline = setTimeout(() => { cancel(); finish(reject, new Error(message)); }, milliseconds);
      signal.addEventListener("abort", abort, {once: true});
      Promise.resolve(work).then(value => finish(resolve, value), error => finish(reject, error));
      if (signal.aborted) abort();
    });
  }
  async function once(target, name, signal) {
    let done, fail;
    const work = new Promise((resolve, reject) => {
      done = resolve; fail = () => reject(new Error("Browser media processing failed."));
      target.addEventListener(name, done, {once: true});
      target.addEventListener("error", fail, {once: true});
      target.addEventListener("abort", fail, {once: true});
    });
    try { await bounded(work, signal, MEDIA_WAIT_MS, "Browser " + name + " timed out."); }
    finally {
      target.removeEventListener(name, done); target.removeEventListener("error", fail);
      target.removeEventListener("abort", fail);
    }
  }
  async function request(path, consume) {
    const pending = new AbortController();
    const abort = () => pending.abort();
    controller.signal.addEventListener("abort", abort, {once: true});
    try {
      const work = fetch(path, {headers, credentials: "omit", mode: "same-origin",
        cache: "no-store", redirect: "error", signal: pending.signal}).then(consume);
      return await bounded(work, controller.signal, REQUEST_MS, "Preview request timed out.", abort);
    } finally { abort(); controller.signal.removeEventListener("abort", abort); }
  }
  function resetMedia() {
    generation += 1;
    if (mediaAbort) mediaAbort.abort();
    mediaAbort = null; buffer = null; media = null; mime = null; installed = null;
    previousStart = null; playing = false; mediaFailed = false; playAttempt = null;
    video.removeAttribute("src"); video.load();
    if (sourceUrl) URL.revokeObjectURL(sourceUrl);
    sourceUrl = null;
  }
  function stop(message) {
    stopped = true; clearTimeout(timer); controller.abort(); resetMedia();
    if (message) status.textContent = message;
  }
  function failedMedia() {
    if (failedGeneration !== generation) { mediaFailures += 1; failedGeneration = generation; }
    mediaFailed = true; playing = false;
    if (mediaAbort) mediaAbort.abort();
  }
  function showPlayback() {
    if (stopped || mediaFailed || installed === null) return;
    status.textContent = userPaused ? "Preview paused. Press play to resume." :
      playBlocked ? "Preview ready. Press play to view." :
      playing && !video.paused ? "Viewing a durable " + current.codec.toUpperCase() + " recording window." :
      "Preview ready. Waiting for browser playback…";
  }
  function seekToWindow() {
    if (!buffer || !current || !buffer.buffered.length) return;
    const ranges = buffer.buffered, last = ranges.length - 1;
    const start = current.decode_start / current.time_scale - origin;
    let contained = false;
    for (let index = 0; index < ranges.length; index += 1) {
      if (video.currentTime >= ranges.start(index) && video.currentTime < ranges.end(index)) contained = true;
    }
    if (!contained || video.currentTime < start - 0.5) {
      video.currentTime = Math.max(start, ranges.start(last));
    }
  }
  function startPlayback() {
    if (userPaused || playBlocked || playAttempt || !video.paused) return;
    const owner = generation, signal = mediaAbort.signal;
    let work;
    try { work = video.play(); }
    catch (error) { work = Promise.reject(error); }
    const attempt = {};
    playAttempt = attempt;
    // This promise owns its deadline, but does not own the manifest polling loop.
    bounded(work, signal, MEDIA_WAIT_MS, "Playback did not start.").then(() => {
      if (owner !== generation || stopped) return;
      playing = !video.paused && video.readyState >= 3; showPlayback();
    }, error => {
      if (owner !== generation || stopped || signal.aborted || userPaused) return;
      if (error.name !== "AbortError") {
        playBlocked = true; playing = false;
        video.pause(); showPlayback();
      }
    }).finally(() => { if (playAttempt === attempt) playAttempt = null; });
  }
  function validate(meta) {
    const integer = value => Number.isSafeInteger(value) && value >= 0;
    if (!meta || !integer(meta.sequence) || meta.sequence === 0 ||
        !integer(meta.time_scale) || meta.time_scale === 0 ||
        !integer(meta.decode_start) || !integer(meta.decode_end) || meta.decode_end <= meta.decode_start) {
      throw new Error("Invalid preview media clock or decode range.");
    }
    if (!integer(meta.initialization_bytes) || !integer(meta.media_bytes) ||
        meta.initialization_bytes === 0 || meta.media_bytes === 0 ||
        !integer(meta.initialization_bytes + meta.media_bytes) ||
        meta.initialization_bytes + meta.media_bytes > 8 * 1024 * 1024 ||
        !integer(meta.samples) || meta.samples === 0 || typeof meta.root !== "string" || meta.root.length > 128 ||
        !["avc", "hevc"].includes(meta.codec) || typeof meta.mime !== "string" || meta.mime.length > 128) {
      throw new Error("Invalid or oversized preview window.");
    }
    if (clock && (meta.time_scale !== clock.time_scale || meta.sequence < clock.sequence ||
        (meta.sequence === clock.sequence && (meta.decode_start !== clock.decode_start ||
          meta.decode_end !== clock.decode_end || meta.root !== clock.root || meta.mime !== clock.mime)) ||
        (meta.sequence > clock.sequence && meta.decode_start < clock.decode_end))) {
      throw new Error("Preview media clock or decode timeline changed. Reopen an active capture link.");
    }
    if (!MediaSourceType.isTypeSupported(meta.mime)) {
      throw new Error("This browser cannot play the selected " + meta.codec.toUpperCase() + " stream.");
    }
    clock = meta;
  }
  async function present(meta, bytes) {
    if (!buffer || mime !== meta.mime || media.readyState !== "open" || video.error) {
      resetMedia();
      mediaAbort = new AbortController(); media = new MediaSourceType(); mime = meta.mime;
      sourceUrl = URL.createObjectURL(media);
      const opened = once(media, "sourceopen", mediaAbort.signal);
      video.src = sourceUrl;
      await opened;
      buffer = media.addSourceBuffer(mime);
      origin = meta.decode_start / meta.time_scale; buffer.timestampOffset = -origin;
    }
    const active = buffer, signal = mediaAbort.signal;
    if (active.updating) await once(active, "updateend", signal);
    // Retain exactly the preceding window, even when window durations change.
    if (previousStart !== null && previousStart > 0 && active.buffered.length &&
        active.buffered.start(0) < previousStart) {
      active.remove(0, previousStart); await once(active, "updateend", signal);
    }
    active.appendBuffer(bytes); await once(active, "updateend", signal);
    const start = meta.decode_start / meta.time_scale - origin;
    const end = meta.decode_end / meta.time_scale - origin;
    let retained = false;
    for (let index = 0; index < active.buffered.length; index += 1) {
      if (active.buffered.end(index) > start && active.buffered.start(index) < end) retained = true;
    }
    if (!retained) throw new Error("The browser did not retain the requested preview window.");
    previousStart = start; current = meta; installed = meta.sequence;
    if (!userPaused) { seekToWindow(); startPlayback(); }
    showPlayback();
  }
  function contentLength(response, bound) {
    const text = response.headers.get("Content-Length");
    const length = text && /^[0-9]+$/.test(text) ? Number(text) : NaN;
    if (!Number.isSafeInteger(length) || length <= 0 || length > bound) {
      throw new Error("Preview response exceeded its bound.");
    }
    return length;
  }
  async function poll() {
    if (stopped || polling) return;
    polling = true;
    let presenting = false;
    try {
      if (mediaFailed) resetMedia();
      const report = await request("/api/manifest", async response => {
        if (!response.ok) throw new Error("Preview access is unavailable (" + response.status + ").");
        contentLength(response, 16384); return response.json();
      });
      if (report.schema !== "fss.live-preview.v1") throw new Error("Unsupported preview format.");
      const meta = report.latest;
      if (!meta) { status.textContent = "Waiting for a durable recording window…"; }
      else {
        validate(meta);
        if (meta.sequence !== installed) {
          const bytes = await request("/api/window/" + meta.sequence, async fragment => {
            if (fragment.status === 404) return null;
            if (!fragment.ok || contentLength(fragment, 8 * 1024 * 1024) !==
                meta.initialization_bytes + meta.media_bytes ||
                fragment.headers.get("X-FSS-Recording-Root") !== meta.root ||
                fragment.headers.get("X-FSS-Window-Sequence") !== String(meta.sequence)) {
              throw new Error("The requested recording window is unavailable.");
            }
            const payload = await fragment.arrayBuffer();
            if (payload.byteLength !== meta.initialization_bytes + meta.media_bytes) {
              throw new Error("Preview transfer ended early.");
            }
            return payload;
          });
          if (bytes === null) {
            unavailable += 1; showDelivery();
            status.textContent = "The requested preview window expired. Waiting for the next durable window…";
          } else {
            presenting = true; await present(meta, bytes); presenting = false;
            if (sequence !== null && meta.sequence > sequence + 1) skipped += meta.sequence - sequence - 1;
            sequence = meta.sequence; showDelivery();
            document.getElementById("window").textContent = String(sequence) + " · " + meta.samples + " pictures";
            document.getElementById("source").textContent = meta.root;
          }
        }
      }
      failures = 0;
    } catch (error) {
      if (stopped || controller.signal.aborted) return;
      if (presenting) failedMedia();
      resetMedia();
      failures += 1;
      status.textContent = error.message || "The capture is no longer reachable.";
      if (failures >= MAX_FAILURES || mediaFailures >= MAX_FAILURES) {
        stop(status.textContent + " Reopen a link from an active capture to reconnect.");
      }
    } finally {
      polling = false;
      if (!stopped) timer = setTimeout(poll, POLL_MS * (2 ** Math.max(0, failures - 1)));
    }
  }
  video.addEventListener("play", () => {
    if (stopped || installed === null) return;
    userPaused = false; playBlocked = false; seekToWindow(); showPlayback();
  });
  video.addEventListener("playing", () => {
    if (stopped || installed === null || mediaFailed || video.paused) return;
    playing = true; userPaused = false; playBlocked = false; mediaFailures = 0; showPlayback();
  });
  video.addEventListener("pause", () => {
    if (stopped || installed === null || !video.paused) return;
    playing = false; if (!playBlocked && !video.ended) userPaused = true; showPlayback();
  });
  for (const event of ["waiting", "stalled", "ended"]) video.addEventListener(event, () => {
    playing = false; showPlayback();
  });
  video.addEventListener("error", () => {
    if (stopped || !media || !video.error) return;
    failedMedia(); status.textContent = "Browser playback failed. Preparing a fresh preview buffer…";
    if (mediaFailures >= MAX_FAILURES) stop("Browser playback failed repeatedly. Reopen an active capture link.");
  });
  addEventListener("pagehide", () => stop(), {once: true});
  poll();
})();
