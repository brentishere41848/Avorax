import { SectionHeading } from "./section-heading";

export function RealtimeGuardSection() {
  return (
    <section className="section-pad bg-[#061120] text-white">
      <div className="container grid gap-12 lg:grid-cols-[1.05fr_0.95fr]">
        <div>
          <SectionHeading
            eyebrow="Real-time protection"
            title="Real-time protection, built to be transparent."
            body="Pasus Guard is designed around visible service state, process monitoring, driver-assisted verdicts where available, and post-launch fallback where driver blocking is unavailable."
            tone="dark"
          />
          <p className="mt-6 rounded-2xl border border-white/12 bg-white/[0.05] p-5 text-sm leading-6 text-white/70">
            Pre-execution blocking requires the driver to be built, signed, installed, and running. Pasus must not claim before-launch blocking unless that path is verified.
          </p>
        </div>
        <div className="grid gap-4">
          {[
            ["Guard Service", "Visible background protection component."],
            ["Process monitoring", "Watches execution events where supported."],
            ["Driver path", "Pre-execution architecture for verified driver installs."],
            ["Fallback mode", "Clear post-launch stopping label when driver blocking is unavailable."],
          ].map(([title, body]) => (
            <div key={title} className="rounded-3xl border border-white/12 bg-white/[0.05] p-6">
              <h3 className="font-extrabold">{title}</h3>
              <p className="mt-2 leading-7 text-white/62">{body}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
