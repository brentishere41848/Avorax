import { WaitlistForm } from "./waitlist-form";
import { SectionHeading } from "./section-heading";

export function WaitlistSection() {
  return (
    <section className="section-pad">
      <div className="container grid gap-10 lg:grid-cols-[0.9fr_1.1fr]">
        <div>
          <SectionHeading
            eyebrow="Waitlist"
            title="Be notified when licensing opens."
            body="Licenses are not available yet. The waitlist is for product updates and release notifications."
          />
        </div>
        <WaitlistForm />
      </div>
    </section>
  );
}
