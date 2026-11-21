"use client";

import { useEffect, useRef, useState } from "react";
import { useFilm } from "./Feed";
import styles from "./DeliveryDropout.module.css";

const base = "/watch/delivery-dropout/";
const label = { complete: "Complete recording", dropout: "Interrupted recording" };
const time = seconds => seconds.toFixed(3).replace(/0+$/, "").replace(/\.$/, "") + " s";

function Recording({ name, side, index, fps, seconds, visible }) {
  const segment = side.frames[index];
  const sourceTime = index / fps;
  const witness = side.witnesses.some(([a, b]) => a <= sourceTime && sourceTime <= b);
  const { source, failure, retry } = useFilm({ video: base + name + ".webp", videoDigest: side.sheetDigest }, visible);
  const [failedImage, setFailedImage] = useState(null);
  const previewFailed = Boolean(failure) || (source && failedImage === source);
  const rows = Math.ceil(side.samples / 8);
  return (
    <div className={styles.recording} data-recording={name} data-segment={segment ?? "unknown"}>
      <div className={styles.camera}><span>{label[name]}</span><span>{side.samples} frames</span></div>
      <div className={styles.screen}>
        {segment !== null && source && !previewFailed ? <img
          src={source} alt={label[name] + ", porch camera at " + time(sourceTime)}
          onError={() => setFailedImage(source)} draggable="false"
          style={{ width: 8 * 100 + "%", height: rows * 100 + "%",
            transform: `translate(${-(segment % 8) * 100 / 8}%, ${-Math.floor(segment / 8) * 100 / rows}%)` }}
        /> : <div className={styles.noPicture}>
          <strong>{segment === null ? "Observation unknown" : previewFailed ? "Frame preview unavailable" : "Checking frame preview"}</strong>
          {segment === null ? <span>No source picture at this time</span>
            : previewFailed && <button type="button" onClick={retry}>Retry preview</button>}
        </div>}
        <span className={styles.stamp}>PORCH &nbsp; +{time(sourceTime)}</span>
      </div>
      <div className={styles.readout}>{segment === null ? "Recording gap" : "Recorded frame " + segment}
        <small>{segment === null ? "No absence claim" : witness ? "Tracker recorded no confirmed entry" : "No absence claim at this instant"}</small>
      </div>
      <div className={styles.band} aria-hidden="true">
        {side.gaps.map(([a, b]) => <i key={a} className={styles.gap} style={{ left: a/seconds*100+"%", width: (b-a)/seconds*100+"%" }} />)}
        {side.witnesses.map(([a, b]) => <i key={a} className={styles.witness} style={{ left: a/seconds*100+"%", width: (b-a)/seconds*100+"%" }} />)}
        <i className={styles.cursor} style={{ left: sourceTime/seconds*100+"%" }} />
      </div>
    </div>
  );
}

export default function DeliveryDropout({ replay }) {
  const [gapStart, gapEnd] = replay.dropout.gaps[0];
  const mid = Math.floor((gapStart + gapEnd) / 2 * replay.fps);
  const total = replay.complete.frames.length;
  const [index, setIndex] = useState(mid);
  const [playing, setPlaying] = useState(false);
  const playStart = useRef(0);
  const section = useRef(null);
  const [visible, setVisible] = useState(false);
  useEffect(() => {
    const observer = new IntersectionObserver(entries => {
      if (entries.some(e => e.isIntersecting)) {
        setVisible(true);
        observer.disconnect();
      }
    }, { rootMargin: "300px" });
    observer.observe(section.current);
    return () => observer.disconnect();
  }, []);
  useEffect(() => {
    if (!playing) return;
    let request;
    function advance(now) {
      const i = Math.max(0, Math.floor((now - playStart.current) * replay.fps / 1000));
      if (i >= total) {
        setIndex(total - 1);
        setPlaying(false);
        return;
      }
      setIndex(i);
      request = requestAnimationFrame(advance);
    }
    request = requestAnimationFrame(advance);
    return () => cancelAnimationFrame(request);
  }, [playing, replay.fps, total]);
  function seek(i) { setPlaying(false); setIndex(i); }
  return (
    <section ref={section} id="delivery-dropout" className={styles.exhibit} data-dropout-digest={replay.digest} aria-labelledby="dropout-title">
      <h3 id="dropout-title">The missing two seconds</h3>
      <p>A courier approaches the porch of this same house. Compare the uninterrupted take with a copy that lost {total - replay.dropout.samples} camera frames. Both follow the original scene clock.</p>
      <div className={styles.pair}>
        {["complete","dropout"].map(name => <Recording key={name} name={name} side={replay[name]} index={index} fps={replay.fps} seconds={replay.seconds} visible={visible} />)}
      </div>
      <div className={styles.legend}><span>Source frame</span><span>Missing input</span><span>No confirmed track entry</span></div>
      <div className={styles.controls}>
        <button type="button" aria-label={playing ? "Pause delivery replay" : "Play delivery replay"} onClick={() => {
          if (!playing) {
            const start = index === total - 1 ? 0 : index;
            setIndex(start);
            playStart.current = performance.now() - start * 1000 / replay.fps;
          }
          setPlaying(!playing);
        }}>{playing ? "Pause" : "Play"}</button>
        <input type="range" aria-label="Delivery replay time" min="0" max={total-1} value={index}
          aria-valuetext={time(index/replay.fps)} onChange={e => seek(Number(e.target.value))} />
        <output>{time(index / replay.fps)}</output>
      </div>
      <div className={styles.markers}>
        {[[gapStart*replay.fps-1,"Last frame before gap"],[mid,"Inside gap"],[gapEnd*replay.fps,"First frame after gap"]].map(([i, s]) =>
          <button type="button" key={i} aria-pressed={index === i} onClick={() => seek(i)}>{s} <small>{time(i / replay.fps)}</small></button>)}
      </div>
      <details>
        <summary>Inspect both native receipts</summary>
        <p>The camera archive samples the <a href={base+"source.mp4"}>staged delivery</a> eight times per second. The native movie reader verified each retained packet. Every surviving packet in the interrupted recording matches the complete recording byte for byte.</p>
        <p>The watch checked frame presentation times across each whole recording and found the two-second gap in the interrupted take. Its <a href="https://github.com/Dicklesworthstone/franken_surveillance_system/blob/main/crates/fss-reference/src/ingest/recorded_coverage.rs">coverage witnesses</a> mark intervals when the tracker recorded no confirmed entry into the porch zone. A picture can return before a new witness is available.</p>
        <ul>{["complete","dropout"].map(name => <li key={name}><strong>{label[name]}</strong>{" · "}
          <a href={base+name+"-import.txt"}>Import receipt</a>{" · "}<a href={base+name+"-movie.txt"}>Frame intervals</a>{" · "}
          {replay[name].reports.map((file, i) => <span key={file}>{i > 0 && " / "}<a href={base+file}>Watch {i+1}</a></span>)}{" · "}
          <a href={base+name+".mkv"}>Download recording</a>
        </li>)}</ul>
      </details>
    </section>
  );
}
