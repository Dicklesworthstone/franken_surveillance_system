import { Link2 } from "lucide-react";
import { exhibitPath, exhibits } from "../lib/exhibits";

export default function SectionLink({ slug }) {
  const label = "Permalink to " + exhibits[slug].label;
  return (
    <a
      className="section-link"
      href={exhibitPath(slug)}
      aria-label={label}
      title={label}
    >
      <Link2 size={16} /> Section link
    </a>
  );
}
