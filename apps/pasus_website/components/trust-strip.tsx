const values = [
  ["Offline-first local scanning", "Core scan and review flows are designed to work without cloud access."],
  ["Visible quarantine", "Confirmed detections stay reviewable before restore or manual deletion."],
  ["Real-time Guard development", "Background protection is built with honest status and fallback labels."],
  ["Licenses coming soon", "Plans are published for roadmap clarity. Payments are not live."],
];

export function TrustStrip() {
  return (
    <section className="relative z-20 -mt-14 pb-16">
      <div className="container grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {values.map(([title, body], index) => (
          <article key={title} className="card p-6">
            <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-[#EAF2FF] text-sm font-extrabold text-[#126BFF]">
              {index + 1}
            </div>
            <h3 className="mt-5 font-extrabold">{title}</h3>
            <p className="mt-3 text-sm leading-6 text-[#5A6678]">{body}</p>
          </article>
        ))}
      </div>
    </section>
  );
}
