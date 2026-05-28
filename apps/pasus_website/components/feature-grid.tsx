const features = [
  [
    "Fast Quick Scan",
    "Targets high-risk locations and risky file types for faster local review.",
  ],
  [
    "Full System Scan",
    "Checks accessible files, respects OS permissions, and reports skipped paths honestly.",
  ],
  [
    "Real-time Guard",
    "Background protection is being prepared for supported desktop platforms.",
  ],
  [
    "Quarantine",
    "Confirmed detections can be isolated without permanent deletion.",
  ],
  [
    "Ransomware Guard",
    "Behavior monitoring watches for rapid destructive file changes.",
  ],
  [
    "Recovery Vault",
    "Restores protected copies when a local recovery source exists.",
  ],
  [
    "Native ML Analysis",
    "Pasus Native Engine model support for local file analysis. Production model updates are still in progress.",
  ],
  [
    "Native Rules",
    "Pasus-owned local rules support signature and behavior review.",
  ],
  [
    "Offline Protection",
    "Core scanning and quarantine are designed to work without an account or internet.",
  ],
  [
    "Allowlist Control",
    "Users can approve trusted files or hashes with clear warnings.",
  ],
];

export function FeatureGrid() {
  return (
    <section className="py-20">
      <div className="container">
        <h2 className="text-4xl font-bold">
          Built for clear endpoint control.
        </h2>
        <div className="mt-10 grid gap-5 md:grid-cols-2 lg:grid-cols-3">
          {features.map(([title, body]) => (
            <article key={title} className="card p-7">
              <div className="mb-5 flex h-11 w-11 items-center justify-center rounded-2xl bg-[#126BFF]/10 font-bold text-[#126BFF]">
                {title.slice(0, 1)}
              </div>
              <h3 className="text-xl font-bold">{title}</h3>
              <p className="mt-3 leading-7 text-[#5B6678]">{body}</p>
            </article>
          ))}
        </div>
      </div>
    </section>
  );
}
