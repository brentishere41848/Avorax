import Link from "next/link";
import { StatusBadge } from "./status-badge";

const plans = [
  {
    name: "Pasus Essential",
    audience: "For personal devices",
    badge: "Coming soon",
    cta: "Notify me",
    featured: false,
    features: ["Quick Scan", "Full Scan", "Quarantine", "Security Events"],
  },
  {
    name: "Pasus Plus",
    audience: "For stronger protection",
    badge: "Planned",
    cta: "Join waitlist",
    featured: true,
    features: [
      "Real-time Guard",
      "Ransomware Guard",
      "Recovery Vault",
      "Native ML Analysis",
    ],
  },
  {
    name: "Pasus Pro",
    audience: "For advanced users and small teams",
    badge: "Coming soon",
    cta: "Contact / Notify me",
    featured: false,
    features: [
      "Lockdown Mode",
      "Policy controls",
      "Advanced logs",
      "Offline protection tools",
    ],
  },
] as const;

export function PricingCards() {
  return (
    <div className="grid gap-6 lg:grid-cols-3">
      {plans.map((plan) => (
        <article
          key={plan.name}
          className={`card relative flex flex-col overflow-hidden p-7 ${plan.featured ? "border-[#126BFF]/35 shadow-[0_28px_90px_rgba(18,107,255,0.16)]" : ""}`}
        >
          {plan.featured ? (
            <div className="absolute inset-x-0 top-0 h-1 bg-[#126BFF]" />
          ) : null}
          <div className="flex items-center justify-between gap-3">
            <StatusBadge tone={plan.featured ? "blue" : "amber"}>
              {plan.badge}
            </StatusBadge>
            <span className="text-xs font-extrabold uppercase tracking-[0.16em] text-[#5A6678]">
              Pricing not announced
            </span>
          </div>
          <h3 className="mt-6 text-2xl font-extrabold tracking-[-0.02em]">
            {plan.name}
          </h3>
          <p className="mt-2 text-[#5A6678]">{plan.audience}</p>
          <ul className="mt-7 flex-1 space-y-4 text-sm font-semibold text-[#334155]">
            {plan.features.map((feature) => (
              <li key={feature} className="flex gap-3">
                <span className="mt-1 h-2 w-2 rounded-full bg-[#16C7A7]" />
                <span>{feature}</span>
              </li>
            ))}
          </ul>
          <Link
            href="/waitlist"
            className={
              plan.featured ? "button-primary mt-8" : "button-light mt-8"
            }
          >
            {plan.cta}
          </Link>
        </article>
      ))}
    </div>
  );
}
