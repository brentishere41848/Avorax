const faqs = [
  [
    "Are licenses available now?",
    "No. Licensing is not live yet, and the website does not offer checkout or license keys.",
  ],
  [
    "Does Pasus work offline?",
    "Core local scanning, quarantine, allowlist, and threat review are designed to work without cloud access.",
  ],
  [
    "Can Pasus replace my current antivirus?",
    "Do not replace your current antivirus until Pasus has completed production validation and independent testing.",
  ],
  [
    "Does Pasus upload my files?",
    "Pasus is designed for local-first scanning. Files should not be uploaded without explicit user consent.",
  ],
  [
    "What platforms are supported?",
    "Windows is the first priority for preview protection. Other platforms may have limited features while development continues.",
  ],
  [
    "What is Native ML?",
    "Native ML is a Pasus Native Engine file-analysis layer intended to run on the device. Production model quality gates are still in progress.",
  ],
  [
    "What does Preview Build mean?",
    "Preview builds are for testing and may be incomplete. Keep Microsoft Defender or your current antivirus enabled.",
  ],
  [
    "Is real-time protection finished?",
    "Real-time Guard is in development. The app must show whether driver blocking, fallback monitoring, or scanner-only protection is actually active.",
  ],
];

export function FaqSection() {
  return (
    <section className="section-pad bg-white">
      <div className="container">
        <div className="max-w-3xl">
          <p className="text-sm font-extrabold uppercase tracking-[0.18em] text-[#126BFF]">
            FAQ
          </p>
          <h2 className="mt-3 text-[34px] font-extrabold leading-[1.05] tracking-[-0.035em] text-[#07111F] md:text-5xl">
            Questions before release.
          </h2>
        </div>
        <div className="mt-10 grid gap-4 md:grid-cols-2">
          {faqs.map(([question, answer]) => (
            <div
              key={question}
              className="rounded-3xl border border-[#DDE7F2] bg-[#F8FBFF] p-6"
            >
              <h3 className="font-extrabold">{question}</h3>
              <p className="mt-3 leading-7 text-[#5A6678]">{answer}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
