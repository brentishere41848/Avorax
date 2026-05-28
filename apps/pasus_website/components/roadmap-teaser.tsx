import Link from "next/link";
import { SectionHeading } from "./section-heading";

export function RoadmapTeaser() {
  return (
    <section className="section-pad">
      <div className="container rounded-[36px] bg-[#061120] p-8 text-white md:p-12">
        <div className="grid gap-8 lg:grid-cols-[1fr_auto] lg:items-end">
          <SectionHeading
            eyebrow="Roadmap"
            title="Built in public, without pretending unfinished work is complete."
            body="Preview builds, real-time protection, driver validation, licensing, signed updates, and production model work are tracked honestly."
            tone="dark"
          />
          <Link href="/roadmap" className="button-secondary w-fit">View roadmap</Link>
        </div>
      </div>
    </section>
  );
}
