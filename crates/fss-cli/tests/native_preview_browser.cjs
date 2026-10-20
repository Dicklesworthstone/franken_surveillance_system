"use strict";

// Executes the repository player unchanged. The event/timer/media interfaces below are
// deterministic browser unit-test interfaces, not a decoder or browser qualification.
const fs = require("node:fs");
const vm = require("node:vm");
const crypto = require("node:crypto");
const assert = require("node:assert/strict");
const test = require("node:test");
const path = require("node:path");
const sourcePath = path.resolve(__dirname, "../src/bin/fss-capture-rtsp/preview/preview.js");
const source = fs.readFileSync(sourcePath, "utf8");
const sourceSha256 = crypto.createHash("sha256").update(source).digest("hex");

const fixture = (sequence, start, end, timeScale = 1000) => ({
  sequence, root: "test-recording-root-" + sequence,
  initialization_bytes: 4, media_bytes: 4, samples: 2,
  decode_start: start * timeScale, decode_end: end * timeScale, time_scale: timeScale,
  codec: "avc", mime: 'video/mp4; codecs="avc1.42C01E"',
});

function browser(windows, behavior = {}) {
  const token = crypto.randomBytes(16).toString("hex");
  let now = 0, nextTimer = 1, manifestIndex = 0, nextUrl = 1, appendErrorUsed = false;
  let activeRequests = 0, maximumRequests = 0;
  const timers = new Map(), urls = new Map(), callbacks = new Map();
  const events = [], fetches = [], appended = [], removed = [], mediaSources = [];
  const fixtureBySequence = new Map(windows.filter(Boolean).map(meta => [meta.sequence, meta]));
  const statuses = [];
  const schedule = (callback, delay = 0) => {
    const id = nextTimer++;
    timers.set(id, {callback, at: now + Math.max(0, Number(delay) || 0)});
    return id;
  };
  const timeRanges = ranges => ({
    get length() { return ranges.length; },
    start(index) { return ranges[index][0]; },
    end(index) { return ranges[index][1]; },
  });
  const merge = ranges => {
    const result = [];
    for (const range of ranges.sort((a, b) => a[0] - b[0])) {
      const last = result[result.length - 1];
      if (last && range[0] <= last[1]) last[1] = Math.max(last[1], range[1]);
      else result.push([...range]);
    }
    return result;
  };
  class SourceBufferInterface extends EventTarget {
    constructor(owner) {
      super(); this.owner = owner; this.updating = false; this.ranges = [];
      this.offset = 0; this.poisoned = false;
    }
    get timestampOffset() { return this.offset; }
    set timestampOffset(value) {
      if (!Number.isFinite(value)) throw new TypeError("timestampOffset must be finite");
      this.offset = value;
    }
    get buffered() { return timeRanges(this.ranges); }
    assertWritable() {
      if (this.updating || this.poisoned || video.error || this.owner.readyState === "closed") {
        throw new DOMException("The media parser cannot accept data", "InvalidStateError");
      }
    }
    appendBuffer(bytes) {
      this.assertWritable();
      const sequence = new Uint8Array(bytes)[0];
      const meta = fixtureBySequence.get(sequence);
      assert(meta, "test payload must identify an actual test window");
      this.updating = true;
      appended.push({at: now, sequence, media: this.owner.id, offset: this.offset});
      if (behavior.appendHang) return;
      schedule(() => {
        this.updating = false;
        if ((behavior.appendError || behavior.appendErrorSequence === sequence) && !appendErrorUsed) {
          appendErrorUsed = true; this.poisoned = true;
          this.owner.readyState = "ended";
          video.error = {code: 3, message: "test user-agent decode refusal"};
          this.dispatchEvent(new Event("error"));
          this.dispatchEvent(new Event("updateend"));
          return;
        }
        const start = meta.decode_start / meta.time_scale + this.offset;
        const end = meta.decode_end / meta.time_scale + this.offset;
        // MSE's default append window excludes negative presentation timestamps.
        if (Number.isFinite(start) && Number.isFinite(end) && end > Math.max(0, start)) {
          this.ranges = merge([...this.ranges, [Math.max(0, start), end]]);
          video.readyState = 4;
        }
        this.dispatchEvent(new Event("updateend"));
      });
    }
    remove(start, end) {
      this.assertWritable();
      assert(Number.isFinite(start) && Number.isFinite(end) && end > start);
      this.updating = true;
      removed.push({at: now, start, end, media: this.owner.id});
      schedule(() => {
        this.ranges = this.ranges.flatMap(([a, b]) => {
          if (b <= start || a >= end) return [[a, b]];
          const kept = [];
          if (a < start) kept.push([a, start]);
          if (b > end) kept.push([end, b]);
          return kept;
        });
        this.updating = false;
        this.dispatchEvent(new Event("updateend"));
      });
    }
    abort() { this.updating = false; this.dispatchEvent(new Event("abort")); }
  }
  class MediaSourceInterface extends EventTarget {
    constructor() {
      super(); this.id = mediaSources.length + 1; this.readyState = "closed";
      this.buffers = []; mediaSources.push(this);
    }
    static isTypeSupported(mime) { return !behavior.unsupportedMime && typeof mime === "string" && mime.startsWith("video/mp4;"); }
    addSourceBuffer() {
      if (this.readyState !== "open") throw new DOMException("source not open", "InvalidStateError");
      const buffer = new SourceBufferInterface(this); this.buffers.push(buffer); return buffer;
    }
    endOfStream() { this.readyState = "ended"; }
  }
  class VideoInterface extends EventTarget {
    constructor() {
      super(); this.source = null; this.time = 0; this.error = null;
      this.paused = true; this.readyState = 0; this.seeks = []; this.playCalls = 0;
      this.autoplay = true; this.ended = false; this.pendingPlays = [];
    }
    set src(url) {
      assert.equal(this.autoplay, false, "automatic source replacement must preserve user pause");
      this.source = urls.get(url); this.error = null; this.time = 0;
      this.paused = true; this.readyState = 0;
      if (!behavior.sourceOpenHang) schedule(() => {
        if (this.source) { this.source.readyState = "open"; this.source.dispatchEvent(new Event("sourceopen")); }
      });
    }
    get currentTime() { return this.time; }
    set currentTime(value) {
      if (!Number.isFinite(value)) throw new TypeError("currentTime must be finite");
      this.time = value; this.seeks.push({at: now, value});
    }
    get buffered() { return this.source?.buffers[0]?.buffered || timeRanges([]); }
    play() {
      this.playCalls++;
      if (behavior.playReject) return Promise.reject(new DOMException("Autoplay permission denied", "NotAllowedError"));
      this.paused = false; this.ended = false;
      schedule(() => this.dispatchEvent(new Event("play")));
      if (behavior.playHang) return new Promise((resolve, reject) => this.pendingPlays.push({resolve, reject}));
      return new Promise(resolve => schedule(() => {
        this.dispatchEvent(new Event("playing")); resolve();
      }));
    }
    pause() {
      this.paused = true;
      const pending = this.pendingPlays.splice(0);
      schedule(() => {
        this.dispatchEvent(new Event("pause"));
        for (const promise of pending) promise.reject(new DOMException("Playback paused", "AbortError"));
      });
    }
    removeAttribute(name) { if (name === "src") this.source = null; }
    load() {
      this.paused = true; this.readyState = 0; this.error = null;
      for (const promise of this.pendingPlays.splice(0)) promise.reject(new DOMException("Media reloaded", "AbortError"));
    }
  }
  const video = new VideoInterface();
  const elements = new Map([["player", video]]);
  for (const name of ["status", "delivery", "window", "source"]) {
    let text = "";
    elements.set(name, {
      get textContent() { return text; },
      set textContent(value) {
        text = String(value);
        if (name === "status") statuses.push({at: now, text, paused: video.paused, readyState: video.readyState});
      },
    });
  }
  const fetch = async (path, options) => {
    assert.equal(options.headers["X-FSS-Read"], "1");
    assert.equal(options.headers["X-FSS-Preview"], token);
    assert.equal(options.mode, "same-origin");
    assert.equal(options.credentials, "omit");
    fetches.push({at: now, path});
    activeRequests += 1;
    maximumRequests = Math.max(maximumRequests, activeRequests);
    options.signal.addEventListener("abort", () => { activeRequests -= 1; }, {once: true});
    if (behavior.requestHang) return new Promise((resolve, reject) => {
      options.signal.addEventListener("abort", () => reject(new DOMException("Request aborted", "AbortError")), {once: true});
    });
    if (path === "/api/manifest") {
      const latest = windows[Math.min(manifestIndex++, windows.length - 1)];
      const report = {schema: "fss.live-preview.v1", state: latest ? "ready" : "waiting", latest};
      return {ok: true, status: 200, headers: new Headers({"Content-Length": String(JSON.stringify(report).length)}), json: async () => report};
    }
    const selected = /^\/api\/window\/(\d+)$/.exec(path);
    assert(selected, "only canonical manifest/window endpoints may be fetched");
    const sequence = Number(selected[1]);
    const meta = fixtureBySequence.get(sequence);
    assert(meta, "manifest sequence must have a prepared fixture");
    if (behavior.expiredSequence === sequence) return {ok: false, status: 404, headers: new Headers()};
    return {ok: true, status: 200,
      headers: new Headers({"Content-Length": "8", "X-FSS-Recording-Root": meta.root, "X-FSS-Window-Sequence": String(meta.sequence)}),
      arrayBuffer: async () => new Uint8Array([sequence, 0, 0, 0, 0, 0, 0, 0]).buffer};
  };
  const location = {hash: "#" + token};
  const clockDate = class extends Date { static now() { return now; } };
  const context = {
    document: {getElementById: id => { assert(elements.has(id), "unknown viewer element " + id); return elements.get(id); }},
    location, history: {replaceState: () => { location.hash = ""; }},
    window: behavior.noMediaSource ? {} : {MediaSource: MediaSourceInterface}, MediaSource: behavior.noMediaSource ? undefined : MediaSourceInterface,
    AbortController, DOMException, Event, EventTarget, Headers, fetch,
    URL: {createObjectURL: media => { const url = "blob:test-" + nextUrl++; urls.set(url, media); return url; },
      revokeObjectURL: url => { urls.delete(url); }},
    setTimeout: schedule, clearTimeout: id => timers.delete(id),
    Date: clockDate, performance: {now: () => now},
    addEventListener: (name, callback) => callbacks.set(name, callback),
  };
  vm.runInNewContext(source, context, {filename: sourcePath, timeout: 1000});
  const flush = () => new Promise(resolve => setImmediate(resolve));
  return {
    video, elements, mediaSources, appended, removed, fetches, statuses, events,
    get timerCount() { return timers.size; },
    get manifestCount() { return manifestIndex; },
    get maximumRequests() { return maximumRequests; },
    get activeRequests() { return activeRequests; },
    async advance(target) {
      await flush();
      let operations = 0;
      while (true) {
        const selected = [...timers].filter(([, timer]) => timer.at <= target)
          .sort((a, b) => a[1].at - b[1].at || a[0] - b[0])[0];
        if (!selected) break;
        assert(++operations <= 2000, "viewer exhausted bounded test event work");
        timers.delete(selected[0]); now = selected[1].at; selected[1].callback(); await flush();
      }
      now = target; await flush();
    },
    async close() { callbacks.get("pagehide")?.(); await flush(); },
    snapshot() {
      return {manifests: manifestIndex, mediaSources: mediaSources.length, appends: appended,
        removals: removed, status: elements.get("status").textContent,
        delivery: elements.get("delivery").textContent, paused: video.paused,
        playCalls: video.playCalls, seeks: video.seeks, timers: timers.size, maximumRequests, activeRequests,
        ranges: mediaSources.flatMap(media => media.buffers.map(buffer => ({media: media.id, ranges: buffer.ranges})))};
    },
  };
}

const checks = [
  ["reaching a window end does not become an explicit user pause", [fixture(1, 0, 2), fixture(2, 2, 4)], {}, 0, async page => {
    page.video.ended = true;
    page.video.pause();
    await page.advance(1000);
    assert.equal(page.video.paused, false);
    assert.equal(page.video.playCalls, 2);
    assert.match(page.elements.get("status").textContent, /viewing/i);
  }],
  ["changing window durations retain exactly the preceding window", [fixture(1, 0, 1), fixture(2, 1, 3), fixture(3, 3, 7), fixture(4, 7, 15)], {}, 1600, page => {
    const ranges = page.mediaSources[0].buffers[0].ranges;
    assert.equal(ranges[0][0], 3, "two earlier windows must not survive a longer incoming window");
    assert.equal(ranges[ranges.length - 1][1], 15);
  }],
  ["a user pause survives a decoder reset and resumes only on user play", [fixture(1, 0, 2), fixture(2, 2, 4), fixture(3, 4, 6)], {appendErrorSequence: 2}, 0, async page => {
    assert.equal(page.video.paused, false);
    assert.equal(page.video.playCalls, 1);
    page.video.pause();
    await page.advance(2000);
    assert(page.mediaSources.length >= 2, "the failed decoder owner must be replaced");
    assert.equal(page.video.paused, true);
    assert.equal(page.video.playCalls, 1, "new fragments cannot resume a user-paused preview");
    assert.match(page.elements.get("status").textContent, /paused/i);
    const resumed = page.video.play();
    await page.advance(2100);
    await resumed;
    assert.equal(page.video.paused, false);
    assert.equal(page.video.playCalls, 2);
    assert.match(page.elements.get("status").textContent, /viewing/i);
  }],
  ["missing MediaSource reports unsupported playback without fetching media", [fixture(1, 0, 2)], {noMediaSource: true}, 30000, page => {
    assert.equal(page.fetches.length, 0);
    assert.match(page.elements.get("status").textContent, /does not support Media Source Extensions/i);
    assert.equal(page.timerCount, 0);
  }],
  ["unsupported codec never downloads an unplayable window", [fixture(1, 0, 2)], {unsupportedMime: true}, 30000, page => {
    assert.equal(page.fetches.filter(item => item.path.startsWith("/api/window/")).length, 0);
    assert.match(page.elements.get("status").textContent, /cannot play/i);
    assert.equal(page.manifestCount, 3);
    assert.equal(page.timerCount, 0);
  }],
  ["invalid media clocks are refused before any append or media transfer", [{...fixture(1, 0, 2), time_scale: 0}], {}, 30000, page => {
    assert.equal(page.appended.length, 0);
    assert.equal(page.fetches.filter(item => item.path.startsWith("/api/window/")).length, 0);
    assert.match(page.elements.get("status").textContent, /invalid.*clock/i);
    assert.equal(page.manifestCount, 3);
    assert.equal(page.timerCount, 0);
  }],
  ["a hung HTTP request is aborted before its finite retry", [fixture(1, 0, 2)], {requestHang: true}, 30000, page => {
    assert.equal(page.fetches.length, 3);
    assert.equal(page.activeRequests, 0);
    assert.equal(page.maximumRequests, 1);
    assert.equal(page.timerCount, 0);
    assert.match(page.elements.get("status").textContent, /timed out.*reopen/i);
  }],
  ["bounded successive windows and visible skip counts", [fixture(1, 0, 2), fixture(2, 2, 4), fixture(3, 4, 6), fixture(5, 8, 10)], {}, 1600, page => {
    assert.equal(page.appended.length, 4);
    assert.equal(page.mediaSources.length, 1);
    const latest = page.mediaSources[0].buffers[0];
    assert(latest.ranges.reduce((sum, [a, b]) => sum + b - a, 0) <= 4, "SourceBuffer must retain at most two equal-duration windows");
    assert.match(page.elements.get("delivery").textContent, /^1 preview windows skipped/);
    assert.equal(page.video.currentTime, 8, "playback must leave an earlier gap and reach the new independent window");
  }],
  ["autoplay refusal must not claim viewing", [fixture(1, 0, 2)], {playReject: true}, 1000, page => {
    assert.equal(page.video.paused, true);
    assert.doesNotMatch(page.elements.get("status").textContent, /\bviewing\b|\blive\b/i);
    assert.match(page.elements.get("status").textContent, /press play|ready/i);
  }],
  ["a media append error resets the poisoned media owner", [fixture(1, 0, 2), fixture(2, 2, 4)], {appendError: true}, 2000, page => {
    assert(page.mediaSources.length >= 2, "append errors require a fresh MediaSource before retrying");
    assert.equal(page.video.error, null);
    assert.equal(page.video.paused, false);
    assert(page.appended.some(item => item.media > 1), "the fresh owner must actually receive another window");
  }],
  ["missing sourceopen is bounded and allows polling or a visible refusal", [fixture(1, 0, 2)], {sourceOpenHang: true}, 30000, page => {
    assert(page.manifestCount > 1 || /timeout|timed out|reopen|unavailable|interrupted/i.test(page.elements.get("status").textContent), "sourceopen wait stalled forever without progress or refusal");
    assert.equal(page.manifestCount, 3);
    assert.equal(page.timerCount, 0);
  }],
  ["missing updateend is bounded and allows polling or a visible refusal", [fixture(1, 0, 2)], {appendHang: true}, 30000, page => {
    assert(page.manifestCount > 1 || /timeout|timed out|reopen|unavailable|interrupted/i.test(page.elements.get("status").textContent), "updateend wait stalled forever without progress or refusal");
    assert.equal(page.manifestCount, 3);
    assert.equal(page.timerCount, 0);
  }],
  ["a pending play promise cannot stall manifest polling forever", [fixture(1, 0, 2), fixture(2, 2, 4)], {playHang: true}, 30000, page => {
    assert(page.manifestCount > 1 || /timeout|timed out|reopen|unavailable|interrupted/i.test(page.elements.get("status").textContent), "play() remained pending and stopped the polling owner");
    assert.equal(page.video.playCalls, 1, "pending autoplay cannot create more playback promises");
    assert.equal(page.video.paused, true);
    assert.doesNotMatch(page.elements.get("status").textContent, /viewing/i);
  }],
  ["a decode clock reset does not silently drop a new window", [fixture(1, 10, 12), fixture(2, 0, 2)], {}, 1000, page => {
    const resetAppend = page.appended.find(item => item.sequence === 2);
    const refused = /reset|clock|timeline|invalid|reopen|unavailable/i.test(page.elements.get("status").textContent);
    assert(refused || (resetAppend && resetAppend.offset === 0 && resetAppend.media > 1), "new decode epoch reused the old negative timestampOffset and was announced as viewed");
  }],
  ["time scale changes are explicitly rebound or refused", [fixture(1, 10, 12), fixture(2, 0, 2, 90000)], {}, 1000, page => {
    const second = page.appended.find(item => item.sequence === 2);
    const refused = /scale|clock|timeline|invalid|reopen|unavailable/i.test(page.elements.get("status").textContent);
    assert(refused || (second && second.media > 1 && second.offset === 0), "different media clock reused a previous time origin without resetting or refusing");
  }],
  ["expired window reports an omission and continues", [fixture(1, 0, 2), fixture(2, 2, 4)], {expiredSequence: 1}, 1200, page => {
    assert.match(page.elements.get("delivery").textContent, /1 requested windows expired/);
    assert(page.appended.some(item => item.sequence === 2));
    assert.equal(page.video.paused, false);
  }],
  ["pagehide aborts a pending browser callback and clears the media source", [fixture(1, 0, 2)], {appendHang: true}, 0, async page => {
    await page.close();
    assert.equal(page.video.source, null);
    const before = page.manifestCount;
    await page.advance(30000);
    assert.equal(page.manifestCount, before);
  }],
];

test("player asset remains within the actual gateway response bound", () => {
  assert(Buffer.byteLength(source) <= 16 * 1024);
  assert.match(sourceSha256, /^[0-9a-f]{64}$/);
});

for (const [name, windows, behavior, deadline, check] of checks) {
  test(name, async context => {
    const page = browser(windows, behavior);
    try {
      await page.advance(deadline);
      await check(page);
      assert(page.maximumRequests <= 1, "only one network response may be active");
    } catch (error) {
      context.diagnostic(JSON.stringify(page.snapshot()));
      throw error;
    } finally { await page.close(); }
  });
}
