export const REPO = "https://github.com/Dicklesworthstone/franken_surveillance_system";

/** Five lenses and the one picture they add up to. */
export function Mark() {
  const spokes = [0, 72, 144, 216, 288].map((deg) => {
    const a = ((deg - 90) * Math.PI) / 180;
    return [13 + 9.5 * Math.cos(a), 13 + 9.5 * Math.sin(a)];
  });
  return (
    <svg viewBox="0 0 26 26" aria-hidden="true">
      <rect width="26" height="26" rx="5" fill="var(--sign)" />
      {spokes.map(([x, y], i) => (
        <line key={i} x1="13" y1="13" x2={x} y2={y} stroke="var(--sign-ink)" strokeWidth="1.3" />
      ))}
      {spokes.map(([x, y], i) => (
        <circle key={i} cx={x} cy={y} r="2" fill="var(--sign-ink)" />
      ))}
      <circle cx="13" cy="13" r="3.6" fill="var(--sign-ink)" />
    </svg>
  );
}

export default function TopBar({ home = "#top" }) {
  return (
    <header className="topbar">
      <a className="skip" href="#minute">
        Skip to the recording
      </a>
      <div className="wrap topbar__row">
        <a className="wordmark" href={home}>
          <Mark />
          Franken Surveillance
        </a>
        <nav aria-label="Sections">
          <ul>
            <li>
              <a href="#minute">The minute</a>
            </li>
            <li>
              <a href="#how">How it works</a>
            </li>
            <li>
              <a href="#status">What runs today</a>
            </li>
            <li className="topbar__keep">
              <a href={REPO}>Source</a>
            </li>
          </ul>
        </nav>
      </div>
    </header>
  );
}
