import { SectionHeading } from "./section-heading";

export function QuarantineRecoverySection() {
  return (
    <section className="section-pad bg-white">
      <div className="container grid items-center gap-12 lg:grid-cols-[0.9fr_1.1fr]">
        <div className="card p-7">
          {["Quarantine metadata", "Restore if false positive", "Manual delete", "Allowlist exact file or hash", "Recovery Vault review"].map((item) => (
            <div key={item} className="flex items-center justify-between border-b border-[#DDE7F2] py-4 last:border-0">
              <span className="font-bold">{item}</span>
              <span className="text-sm font-bold text-[#126BFF]">Visible</span>
            </div>
          ))}
        </div>
        <div>
          <SectionHeading
            eyebrow="Quarantine and recovery"
            title="Threats stay visible and under control."
            body="Pasus stores quarantine metadata, supports restore review for false positives, and avoids permanent deletion unless the user confirms it."
          />
          <p className="mt-6 rounded-2xl bg-[#FFF6DF] p-5 text-sm leading-6 text-[#665000]">
            Recovery depends on available backups, snapshots, or Recovery Vault copies. Pasus does not claim encrypted files can always be restored.
          </p>
        </div>
      </div>
    </section>
  );
}
