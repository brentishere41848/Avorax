type StatusTone = "blue" | "green" | "amber" | "dark" | "muted";

const tones: Record<StatusTone, string> = {
  blue: "bg-[#EAF2FF] text-[#0B4FD8]",
  green: "bg-[#E9FFF8] text-[#087B69]",
  amber: "bg-[#FFF6DF] text-[#8A5A00]",
  dark: "bg-[#07111F] text-white",
  muted: "bg-[#F5F8FC] text-[#5A6678]",
};

export function StatusBadge({
  children,
  tone = "blue",
}: {
  children: React.ReactNode;
  tone?: StatusTone;
}) {
  return <span className={`pill ${tones[tone]}`}>{children}</span>;
}
