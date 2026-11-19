import "@fontsource-variable/space-grotesk/index.css";
import "@fontsource/ibm-plex-mono/latin-400.css";
import "@fontsource/instrument-serif/latin-400.css";
import "@fontsource/instrument-serif/latin-400-italic.css";
import "./estate.css";
export const metadata = {
  metadataBase: new URL("https://franken-surveillance.com"),
  title: "Franken Surveillance · Alder House",
  description:
    "Home security after dark. Explore a fictional estate, review three camera feeds and follow the source evidence behind an alert.",
};
export default function Layout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
