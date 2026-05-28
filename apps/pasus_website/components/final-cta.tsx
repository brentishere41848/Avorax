import Link from "next/link";

export function FinalCta() {
  return (
    <section className="pb-24">
      <div className="container rounded-[36px] bg-white p-8 shadow-[0_24px_80px_rgba(8,24,48,0.10)] md:p-12">
        <div className="grid gap-6 md:grid-cols-[1fr_auto] md:items-center">
          <div>
            <h2 className="text-3xl font-extrabold tracking-[-0.03em] md:text-5xl">Ready to follow Pasus?</h2>
            <p className="mt-4 text-lg leading-8 text-[#5A6678]">Join the waitlist or test the current preview build when release assets are available.</p>
          </div>
          <div className="flex flex-wrap gap-3">
            <Link href="/waitlist" className="button-primary">Join waitlist</Link>
            <Link href="/download" className="button-light">Download preview</Link>
          </div>
        </div>
      </div>
    </section>
  );
}
