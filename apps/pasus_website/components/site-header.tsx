import Image from "next/image";
import Link from "next/link";
import { siteConfig } from "../lib/site-config";

export function SiteHeader() {
  return (
    <header className="sticky top-0 z-50 border-b border-[#DDE7F2] bg-white/92 backdrop-blur-xl">
      <div className="container flex h-20 items-center justify-between gap-6">
        <Link href="/" className="flex min-w-0 items-center gap-3 font-extrabold tracking-[-0.02em]">
          <Image src="/pasus-logo.svg" alt="" width={42} height={42} />
          <span className="truncate text-lg">{siteConfig.name}</span>
        </Link>
        <nav className="hidden items-center gap-7 text-sm font-semibold text-[#5B6678] lg:flex">
          {siteConfig.nav.map((item) => (
            <Link key={item.href} href={item.href} className="transition hover:text-[#07111F]">
              {item.label}
            </Link>
          ))}
        </nav>
        <div className="ml-auto flex shrink-0 items-center gap-3">
          <Link
            href="/waitlist"
            className="hidden rounded-full border border-[#E1E7EF] px-5 py-3 text-sm font-bold md:inline-flex"
          >
            Join waitlist
          </Link>
          <Link
            href="/download"
            className="hidden rounded-full bg-[#126BFF] px-5 py-3 text-sm font-extrabold text-white shadow-[0_12px_30px_rgba(18,107,255,0.22)] transition hover:bg-[#0B4FD8] sm:inline-flex"
          >
            Download preview
          </Link>
          <details className="mobile-menu-trigger">
            <summary className="flex h-11 w-11 cursor-pointer list-none items-center justify-center rounded-full border border-[#DDE7F2] bg-white text-lg font-extrabold text-[#07111F] shadow-sm">
              =
            </summary>
            <div className="absolute right-0 top-14 w-72 rounded-3xl border border-[#DDE7F2] bg-white p-3 shadow-[0_24px_80px_rgba(8,24,48,0.16)]">
              {siteConfig.nav.map((item) => (
                <Link key={item.href} href={item.href} className="block rounded-2xl px-4 py-3 text-sm font-bold text-[#5A6678] hover:bg-[#F5F8FC] hover:text-[#07111F]">
                  {item.label}
                </Link>
              ))}
            </div>
          </details>
        </div>
      </div>
    </header>
  );
}
