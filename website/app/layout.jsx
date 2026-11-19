import "@fontsource-variable/space-grotesk/index.css";
import "@fontsource/ibm-plex-mono/latin-400.css";
import "./style.css";
export const metadata = {
  metadataBase: new URL("https://franken-surveillance.com"),
  title: "Property Observatory · Franken Surveillance",
  description:
    "Explore Juniper House in 3D, replay three virtual cameras, and inspect what the Franken Surveillance reference implementation measured.",
  openGraph: { images: ["/films/property.jpg"] },
};
export default function Layout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
