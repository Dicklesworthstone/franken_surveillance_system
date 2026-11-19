import "@fontsource-variable/space-grotesk/index.css";
import "@fontsource/ibm-plex-mono/latin-400.css";
import "@fontsource/instrument-serif/latin-400.css";
import "@fontsource/instrument-serif/latin-400-italic.css";
import "./style.css";
import "./field.css";
import "./motion.css";
import "./courtyard.css";
import "./stereo.css";
export const metadata = {
  metadataBase: new URL("https://franken-surveillance.com"),
  title: "Franken Surveillance · The Home Control Room",
  description:
    "Explore a home digital twin, compare camera observations, verify a published event and inspect the native agent response.",
};
export default function Layout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
