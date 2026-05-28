import { ProtectionStackSection } from "../../components/protection-stack-section";
import { QuarantineRecoverySection } from "../../components/quarantine-recovery-section";
import { RealtimeGuardSection } from "../../components/realtime-guard-section";

export default function ProtectionPage() {
  return (
    <>
      <section className="bg-white py-20">
        <div className="container">
          <h1 className="text-[42px] font-extrabold leading-[1.02] tracking-[-0.05em] md:text-6xl">Prevention-first protection, stated honestly.</h1>
          <p className="mt-5 max-w-3xl leading-8 text-[#5B6678]">
            Pasus uses local scanning, policy, quarantine, and behavior monitoring. Driver-level blocking is shown only when installed and verified.
          </p>
        </div>
      </section>
      <RealtimeGuardSection />
      <ProtectionStackSection />
      <QuarantineRecoverySection />
    </>
  );
}
