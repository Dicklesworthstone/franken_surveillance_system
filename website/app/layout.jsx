import "@fontsource-variable/space-grotesk/index.css";
import "@fontsource/ibm-plex-mono/latin-400.css";
import "@fontsource/instrument-serif/latin-400.css";
import "@fontsource/instrument-serif/latin-400-italic.css";
import "./estate.css";
export const metadata = {
  metadataBase: new URL("https://franken-surveillance.com"),
  title: "Franken Surveillance",
  description:
    "Replay a residential security alert from multiple cameras, inspect the property in 3D and verify the evidence behind an agent’s assessment.",
};
export default function Layout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
