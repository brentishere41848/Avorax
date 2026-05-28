import { SectionHeading } from "./section-heading";

const layers = [
  "Application Control",
  "Signature Detection",
  "Native Rules",
  "Native ML Analysis",
  "Heuristic Scoring",
  "Behavior Monitoring",
  "Quarantine",
  "Recovery Vault",
];

export function ProtectionStackSection() {
  return (
    <section className="section-pad">
      <div className="container">
        <SectionHeading
          eyebrow="Layered protection"
          title="A clear stack from policy to recovery."
          body="Each layer contributes to an auditable local decision instead of hiding behind vague protection claims."
          align="center"
        />
        <div className="mx-auto mt-12 max-w-4xl">
          {layers.map((layer, index) => (
            <div
              key={layer}
              className="mb-3 grid grid-cols-[72px_1fr] items-center gap-4 rounded-3xl border border-[#DDE7F2] bg-white p-4 shadow-sm"
            >
              <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-[#EAF2FF] font-extrabold text-[#126BFF]">
                {String(index + 1).padStart(2, "0")}
              </div>
              <div>
                <h3 className="font-extrabold">{layer}</h3>
                <p className="mt-1 text-sm text-[#5A6678]">
                  Part of the prevention and review pipeline.
                </p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
