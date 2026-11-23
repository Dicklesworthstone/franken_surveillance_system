import TopBarNav from "./TopBarNav";

export const REPO = "https://github.com/Dicklesworthstone/franken_surveillance_system";

/** Five lenses and the one picture they add up to. */
export function Mark() {
  const spokes = [0, 72, 144, 216, 288].map((deg) => {
    const a = ((deg - 90) * Math.PI) / 180;
    // Rounded so that the server and the browser write the same digits.
    return [13 + 9.5 * Math.cos(a), 13 + 9.5 * Math.sin(a)].map((n) => +n.toFixed(3));
  });
  return (
    <svg viewBox="0 0 26 26" aria-hidden="true">
      <rect width="26" height="26" rx="7.5" fill="var(--lamp)" />
      {spokes.map(([x, y], i) => (
        <line key={i} x1="13" y1="13" x2={x} y2={y} stroke="var(--lamp-ink)" strokeWidth="1.3" />
      ))}
      {spokes.map(([x, y], i) => (
        <circle key={i} cx={x} cy={y} r="2" fill="var(--lamp-ink)" />
      ))}
      <circle cx="13" cy="13" r="3.6" fill="var(--lamp-ink)" />
    </svg>
  );
}

export default function TopBar({ home = "#top" }) {
  return (
    <>
      <a className="skip" href="#console">
        Skip to the replay
      </a>
      <TopBarNav repo={REPO} home={home} mark={<Mark />} />
    </>
  );
}
