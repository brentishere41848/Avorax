import Link from "next/link";
import { SectionHeading } from "./section-heading";
import { StatusBadge } from "./status-badge";

export function DownloadPreviewSection() {
  return (
    <section className="section-pad bg-white">
      <div className="container grid items-center gap-10 lg:grid-cols-[0.9fr_1.1fr]">
        <div>
          <SectionHeading
            eyebrow="Preview download"
            title="Preview builds for testing."
            body="The download page links to real release assets when GitHub Releases provide them. It never invents installer links."
          />
          <p className="mt-6 rounded-2xl bg-[#FFF6DF] p-5 text-sm leading-6 text-[#665000]">
            Preview builds are for testing. Keep Microsoft Defender or your current antivirus enabled.
          </p>
        </div>
        <div className="grid gap-4 sm:grid-cols-2">
          {["Windows MSI", "Windows Setup EXE", "Release notes", "Checksums"].map((item) => (
            <div key={item} className="card p-6">
              <StatusBadge tone="muted">Release asset</StatusBadge>
              <h3 className="mt-5 text-xl font-extrabold">{item}</h3>
              <p className="mt-2 text-sm leading-6 text-[#5A6678]">Preview build link not configured unless the release pipeline publishes this asset.</p>
            </div>
          ))}
          <Link href="/download" className="button-primary sm:col-span-2">Open download page</Link>
        </div>
      </div>
    </section>
  );
}
