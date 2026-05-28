import Link from "next/link";

const groups: Array<[string, Array<[string, string]>]> = [
  ["Product", [["Features", "/product"], ["Pricing", "/pricing"], ["Download", "/download"], ["Roadmap", "/roadmap"]]],
  ["Protection", [["Real-time Protection", "/protection"], ["Quarantine", "/protection"], ["Recovery Vault", "/protection"], ["Lockdown Mode", "/protection"]]],
  ["Resources", [["Privacy", "/privacy"], ["Terms", "/terms"], ["Limitations", "/roadmap"], ["Release Notes", "/download"]]],
];

export function SiteFooter() {
  return (
    <footer className="bg-[#07111F] py-16 text-white">
      <div className="container grid gap-10 md:grid-cols-[1.4fr_2fr]">
        <div>
          <h2 className="text-2xl font-bold">Pasus Anti-Malware</h2>
          <p className="mt-4 max-w-md text-sm leading-6 text-white/68">
            Prevention-first endpoint protection in active development. Licenses coming soon. Preview builds only.
          </p>
          <p className="mt-6 text-xs text-white/50">
            Pasus is in active development. No anti-malware product can guarantee protection against every threat.
          </p>
        </div>
        <div className="grid gap-8 sm:grid-cols-3">
          {groups.map(([title, links]) => (
            <div key={title}>
              <h3 className="font-bold">{title}</h3>
              <ul className="mt-4 space-y-3 text-sm text-white/66">
                {links.map(([label, href]) => (
                  <li key={label}>
                    <Link href={href} className="transition hover:text-white">{label}</Link>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
        <div className="md:col-span-2 grid gap-3 border-t border-white/10 pt-8 text-sm text-white/58 sm:grid-cols-3">
          <span>Licenses coming soon</span>
          <span>Preview builds only</span>
          <span>No fake certifications</span>
        </div>
      </div>
    </footer>
  );
}
