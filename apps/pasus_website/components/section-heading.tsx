export function SectionHeading({
  eyebrow,
  title,
  body,
  align = "left",
  tone = "light",
}: {
  eyebrow?: string;
  title: string;
  body?: string;
  align?: "left" | "center";
  tone?: "light" | "dark";
}) {
  const dark = tone === "dark";
  return (
    <div className={align === "center" ? "mx-auto max-w-3xl text-center" : "max-w-3xl"}>
      {eyebrow ? <p className={`text-sm font-extrabold uppercase tracking-[0.18em] ${dark ? "text-[#16C7A7]" : "text-[#126BFF]"}`}>{eyebrow}</p> : null}
      <h2 className={`mt-3 text-[34px] font-extrabold leading-[1.05] tracking-[-0.035em] md:text-5xl ${dark ? "text-white" : "text-[#07111F]"}`}>
        {title}
      </h2>
      {body ? <p className={`mt-5 text-lg leading-8 ${dark ? "text-white/68" : "text-[#5A6678]"}`}>{body}</p> : null}
    </div>
  );
}
