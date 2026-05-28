import { SectionHeading } from "./section-heading";
import { StatusBadge } from "./status-badge";

const checklist = [
  "Startup locations",
  "Temp folders",
  "Downloads",
  "Running process paths",
  "Recent risky files",
  "Executable and script types",
];

export function QuickScanSection() {
  return (
    <section className="section-pad soft-grid">
      <div className="container grid items-center gap-12 lg:grid-cols-[0.95fr_1.05fr]">
        <div>
          <SectionHeading
            eyebrow="Fast scanning"
            title="Quick scans that focus on the risky places first."
            body="Pasus Quick Scan prioritizes locations and file types that matter for routine checks. It does not require cloud access."
          />
          <div className="mt-8 grid gap-3 text-[#334155] sm:grid-cols-2">
            {checklist.map((item) => (
              <div key={item} className="flex items-center gap-3 rounded-2xl border border-[#DDE7F2] bg-white px-4 py-3 font-semibold">
                <span className="h-2.5 w-2.5 rounded-full bg-[#16C7A7]" />
                {item}
              </div>
            ))}
          </div>
        </div>
        <div className="card p-7">
          <div className="flex items-center justify-between gap-4">
            <h3 className="text-2xl font-extrabold">Quick Scan plan</h3>
            <StatusBadge tone="green">No cloud required</StatusBadge>
          </div>
          <div className="mt-7 space-y-4">
            {["Planning", "Startup locations", "Running processes", "Recent risky files", "High-risk folders"].map((step, index) => (
              <div key={step} className="flex items-center gap-4 rounded-2xl bg-[#F5F8FC] p-4">
                <span className="flex h-9 w-9 items-center justify-center rounded-full bg-[#EAF2FF] text-sm font-extrabold text-[#126BFF]">{index + 1}</span>
                <div>
                  <p className="font-bold">{step}</p>
                  <p className="text-sm text-[#5A6678]">Design stage label, not fake scan output.</p>
                </div>
              </div>
            ))}
          </div>
          <div className="mt-5 rounded-2xl border border-[#DDE7F2] bg-[#E9FFF8] p-4 text-sm font-semibold text-[#087B69]">
            Verdict caching is used to avoid unnecessary repeat work where safe.
          </div>
        </div>
      </div>
    </section>
  );
}
