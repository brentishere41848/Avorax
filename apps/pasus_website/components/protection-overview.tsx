import { FeatureCard } from "./feature-card";
import { SectionHeading } from "./section-heading";

const features = [
  [
    "Quick Scan",
    "Focuses on risky locations and file types first so routine checks do not feel like full disk sweeps.",
    "Available",
    "↯",
  ],
  [
    "Full Scan",
    "Checks accessible local files, skips denied paths safely, and reports real scan progress.",
    "Available",
    "◎",
  ],
  [
    "Real-time Guard",
    "Background monitoring and blocking paths are being prepared with explicit status reporting.",
    "In development",
    "◼",
  ],
  [
    "Quarantine",
    "Moves confirmed detections into a controlled local store with metadata and restore controls.",
    "Preview",
    "□",
  ],
  [
    "Recovery Vault",
    "Keeps recovery workflows visible. Restore depends on available protected copies or snapshots.",
    "Preview",
    "↺",
  ],
  [
    "Native ML Analysis",
    "Offline PNE model support helps file analysis. Production model updates and licensing are still in progress.",
    "In development",
    "◇",
  ],
] as const;

export function ProtectionOverview() {
  return (
    <section className="section-pad bg-white">
      <div className="container">
        <SectionHeading
          eyebrow="Protection overview"
          title="Security tools without the black box."
          body="Pasus is designed to show what it checked, why an item needs review, and what action was taken."
          align="center"
        />
        <div className="mt-12 grid gap-5 md:grid-cols-2 lg:grid-cols-3">
          {features.map(([title, body, status, icon]) => (
            <FeatureCard
              key={title}
              title={title}
              body={body}
              status={status}
              icon={icon}
            />
          ))}
        </div>
      </div>
    </section>
  );
}
