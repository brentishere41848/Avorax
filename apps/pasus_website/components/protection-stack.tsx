import { SecurityDisclaimer } from "./security-disclaimer";

const layers = [
  "Signature detection",
  "Native rules",
  "Native ML analysis",
  "Heuristic scoring",
  "Behavior monitoring",
  "Quarantine",
  "Recovery Vault",
  "Lockdown Mode",
];

export function ProtectionStack() {
  return (
    <section className="bg-white py-20">
      <div className="container grid gap-10 lg:grid-cols-[0.9fr_1.1fr]">
        <div>
          <p className="font-bold text-[#126BFF]">Protection stack</p>
          <h2 className="mt-3 text-4xl font-bold">
            Multiple local signals, one visible decision.
          </h2>
          <p className="mt-5 leading-8 text-[#5B6678]">
            Pasus combines local engines and policy controls so users can see
            why a file was blocked, reviewed, or quarantined.
          </p>
          <div className="mt-8">
            <SecurityDisclaimer />
          </div>
        </div>
        <div className="grid gap-4 sm:grid-cols-2">
          {layers.map((layer, index) => (
            <div key={layer} className="card p-5">
              <span className="text-sm font-bold text-[#126BFF]">
                Layer {index + 1}
              </span>
              <h3 className="mt-2 font-bold">{layer}</h3>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
