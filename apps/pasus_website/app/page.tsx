import { DownloadPreviewSection } from "../components/download-preview-section";
import { FinalCta } from "../components/final-cta";
import { FaqSection } from "../components/faq-section";
import { HeroSection } from "../components/hero-section";
import { PricingCards } from "../components/pricing-cards";
import { ProtectionOverview } from "../components/protection-overview";
import { ProtectionStackSection } from "../components/protection-stack-section";
import { QuarantineRecoverySection } from "../components/quarantine-recovery-section";
import { QuickScanSection } from "../components/quick-scan-section";
import { RealtimeGuardSection } from "../components/realtime-guard-section";
import { RoadmapTeaser } from "../components/roadmap-teaser";
import { SectionHeading } from "../components/section-heading";
import { TrustStrip } from "../components/trust-strip";
import { WaitlistSection } from "../components/waitlist-section";

export default function HomePage() {
  return (
    <>
      <HeroSection />
      <TrustStrip />
      <ProtectionOverview />
      <QuickScanSection />
      <RealtimeGuardSection />
      <QuarantineRecoverySection />
      <ProtectionStackSection />
      <section className="section-pad bg-white">
        <div className="container">
          <SectionHeading
            eyebrow="Licensing"
            title="Pasus licenses are coming soon."
            body="Join the waitlist to be notified when paid plans open. No checkout, payment flow, or license key generation is live yet."
            align="center"
          />
          <div className="mt-12">
            <PricingCards />
          </div>
        </div>
      </section>
      <DownloadPreviewSection />
      <RoadmapTeaser />
      <WaitlistSection />
      <FaqSection />
      <FinalCta />
    </>
  );
}
