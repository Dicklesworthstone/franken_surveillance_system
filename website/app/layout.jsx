import localFont from "next/font/local";
import "./styles/index.css";

// Inter carries its optical sizes, so a headline is set in the display cut and a caption in the text cut.
const sans = localFont({
  src: "../node_modules/@fontsource-variable/inter/files/inter-latin-opsz-normal.woff2",
  weight: "100 900",
  variable: "--font-sans",
  display: "swap",
});
const mono = localFont({
  src: "../node_modules/@fontsource-variable/jetbrains-mono/files/jetbrains-mono-latin-wght-normal.woff2",
  weight: "100 800",
  variable: "--font-mono",
  display: "swap",
  // Set in labels and readouts only; the headline and the body text do not wait for it.
  preload: false,
});

const title = "Franken Surveillance: a pure-Rust security room built from $35 cameras";
const description =
  "Open-source, local-first pure-Rust software that joins cheap Wi-Fi cameras from any mix of makers into one calibrated model of your property, records what it saw, says what it could not see, keeps a crash-safe record and gives an AI agent a bounded place to watch and act.";

export const metadata = {
  metadataBase: new URL("https://franken-surveillance.com"),
  title,
  description,
  alternates: { canonical: "/" },
  openGraph: { type: "website", url: "/", siteName: "Franken Surveillance", title, description },
  twitter: { card: "summary_large_image", title, description },
};
export const viewport = { themeColor: "#05070b", colorScheme: "dark", viewportFit: "cover" };

export default function Layout({ children }) {
  return (
    <html lang="en" className={`${sans.variable} ${mono.variable}`}>
      <body>{children}</body>
    </html>
  );
}
