"use client";
import { useEffect, useRef } from "react";
import { ChevronDown } from "lucide-react";
import { exhibitPath, exhibits } from "../lib/exhibits";
const groups = [
  [
    "Explore the site",
    [
      "courtyard",
      "motion-study",
      "digital-twin",
      "camera-wall",
      "film-archive",
    ],
  ],
  [
    "Examine the evidence",
    [
      "camera-inputs",
      "camera-fusion",
      "belief-lab",
      "event-ledger",
      "field-method",
    ],
  ],
  ["Follow the decision", ["agent-console", "owner-response"]],
];
export default function ExhibitMenu({ current }) {
  const menu = useRef(null);
  useEffect(() => {
    const outside = (e) => {
      if (menu.current?.open && !menu.current.contains(e.target))
        menu.current.open = false;
    };
    const escape = (e) => {
      if (e.key === "Escape" && menu.current?.open) {
        menu.current.open = false;
        menu.current.querySelector("summary").focus();
      }
    };
    document.addEventListener("pointerdown", outside);
    document.addEventListener("keydown", escape);
    return () => {
      document.removeEventListener("pointerdown", outside);
      document.removeEventListener("keydown", escape);
    };
  }, []);
  return (
    <details className="exhibit-menu" ref={menu}>
      <summary>
        Exhibits <ChevronDown size={14} />
      </summary>
      <div className="exhibit-catalog">
        {groups.map(([name, ids]) => (
          <div key={name}>
            <strong>{name}</strong>
            {ids.map((id) => (
              <a
                key={id}
                href={exhibitPath(id)}
                aria-current={id === current ? "page" : undefined}
              >
                {exhibits[id].label}
              </a>
            ))}
          </div>
        ))}
      </div>
    </details>
  );
}
