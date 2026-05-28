import { FaqSection } from "../../components/faq-section";
import { LicenseComingSoon } from "../../components/license-coming-soon";
import { PricingCards } from "../../components/pricing-cards";
import { SectionHeading } from "../../components/section-heading";

export default function PricingPage() {
  return (
    <>
      <section className="bg-white section-pad">
        <div className="container">
          <SectionHeading
            eyebrow="Coming soon"
            title="Licensing is not live yet."
            body="Pasus plan names and capabilities are published for roadmap transparency. Checkout and license keys are not available."
            align="center"
          />
          <div className="mt-12">
            <PricingCards />
          </div>
        </div>
      </section>
      <LicenseComingSoon />
      <FaqSection />
    </>
  );
}
