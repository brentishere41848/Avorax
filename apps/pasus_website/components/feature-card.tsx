import { StatusBadge } from "./status-badge";

export function FeatureCard({
  title,
  body,
  status,
  icon,
}: {
  title: string;
  body: string;
  status: "Available" | "Preview" | "In development" | "Coming soon";
  icon: string;
}) {
  const tone = status === "Available" ? "green" : status === "Preview" ? "blue" : status === "Coming soon" ? "amber" : "muted";
  return (
    <article className="card group p-7 transition duration-200 hover:-translate-y-1 hover:shadow-[0_26px_70px_rgba(8,24,48,0.12)]">
      <div className="flex items-start justify-between gap-4">
        <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-[#EAF2FF] text-xl">{icon}</div>
        <StatusBadge tone={tone}>{status}</StatusBadge>
      </div>
      <h3 className="mt-6 text-xl font-extrabold tracking-[-0.015em]">{title}</h3>
      <p className="mt-3 leading-7 text-[#5A6678]">{body}</p>
    </article>
  );
}
