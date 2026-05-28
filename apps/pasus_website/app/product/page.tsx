import { ProtectionOverview } from "../../components/protection-overview";
import { QuickScanSection } from "../../components/quick-scan-section";
import { SecurityDisclaimer } from "../../components/security-disclaimer";

export default function ProductPage() {
  return (
    <>
      <section className="bg-[#061120] py-24 text-white">
        <div className="container">
          <h1 className="max-w-3xl text-[42px] font-extrabold leading-[1.02] tracking-[-0.05em] md:text-6xl">Endpoint protection with local visibility.</h1>
          <p className="mt-5 max-w-3xl leading-8 text-white/72">
            Pasus Anti-Malware focuses on fast scans, transparent risk reasons, quarantine controls, and offline-first protection workflows.
          </p>
        </div>
      </section>
      <ProtectionOverview />
      <QuickScanSection />
      <section className="py-16">
        <div className="container">
          <SecurityDisclaimer />
        </div>
      </section>
    </>
  );
}
