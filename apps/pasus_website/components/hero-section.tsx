import Link from "next/link";
import { ProductPreview } from "./product-preview";

export function HeroSection() {
  return (
    <section className="relative overflow-hidden bg-[#061120] text-white">
      <div className="absolute inset-x-0 top-0 h-px bg-white/10" aria-hidden="true" />
      <div className="container grid min-h-[720px] items-center gap-16 py-20 lg:grid-cols-[1.02fr_0.98fr] lg:py-24">
        <div className="max-w-3xl">
          <div className="inline-flex rounded-full border border-white/14 bg-white/[0.07] px-4 py-2 text-sm font-extrabold text-[#16C7A7] shadow-[inset_0_1px_0_rgba(255,255,255,0.08)]">
            License sales: Coming soon
          </div>
          <h1 className="mt-8 max-w-[350px] text-[30px] font-extrabold leading-[1.06] tracking-[-0.035em] text-white sm:max-w-none sm:text-[44px] md:text-[64px] md:leading-[0.98] md:tracking-[-0.055em]">
            Anti-malware protection built for speed, control, and clarity.
          </h1>
          <p className="mt-7 max-w-2xl text-lg leading-8 text-white/70 md:text-xl md:leading-9">
            Pasus helps scan, block, quarantine, and review threats locally. Real-time protection, licensing, and production validation are being prepared for release.
          </p>
          <div className="mt-9 flex flex-wrap gap-4">
            <Link href="/waitlist" className="button-primary">
              Join the license waitlist
            </Link>
            <Link href="/download" className="button-secondary">
              Download preview build
            </Link>
          </div>
          <div className="mt-10 grid gap-3 text-sm font-semibold text-white/74 sm:grid-cols-2">
            {[
              "Works offline for local scans",
              "Visible quarantine and threat review",
              "Real-time Guard in development",
              "No hidden surveillance",
            ].map((item) => (
              <div key={item} className="flex items-center gap-3">
                <span className="h-2 w-2 rounded-full bg-[#16C7A7]" />
                {item}
              </div>
            ))}
          </div>
        </div>
        <div className="lg:pl-2">
          <ProductPreview />
        </div>
      </div>
    </section>
  );
}
