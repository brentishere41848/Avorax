import Image from "next/image";
import { StatusBadge } from "./status-badge";

const scanOptions = ["Quick Scan", "Full Scan", "Custom Scan"];
const engines = [
  ["Native rules", "Loaded"],
  ["Native ML", "Development"],
  ["Quarantine", "Ready"],
  ["Recovery Vault", "Preview"],
];

export function ProductPreview() {
  return (
    <div className="relative mx-auto w-full max-w-[620px] overflow-hidden">
      <div
        className="absolute -inset-5 rounded-[44px] bg-[#126BFF]/20 blur-3xl"
        aria-hidden="true"
      />
      <div className="relative min-w-0 rounded-[30px] border border-white/14 bg-white/[0.08] p-2 shadow-2xl shadow-black/30 backdrop-blur sm:rounded-[36px] sm:p-3">
        <div className="min-w-0 rounded-[24px] border border-white/12 bg-[#07111F] p-4 sm:rounded-[28px] sm:p-5">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/10 pb-5">
            <div className="flex min-w-0 items-center gap-3">
              <Image src="/pasus-logo.svg" alt="" width={38} height={38} />
              <div className="min-w-0">
                <p className="text-sm font-extrabold text-white">
                  Pasus Protection Console
                </p>
                <p className="text-xs text-white/50">
                  Endpoint preview interface
                </p>
              </div>
            </div>
            <span className="hidden sm:inline-flex">
              <StatusBadge tone="green">Preview build</StatusBadge>
            </span>
          </div>

          <div className="mt-5 rounded-3xl border border-white/10 bg-white/[0.04] p-5">
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div>
                <p className="text-xs font-bold uppercase tracking-[0.18em] text-[#16C7A7]">
                  Main status
                </p>
                <h3 className="mt-2 text-2xl font-extrabold text-white">
                  Local protection ready
                </h3>
                <p className="mt-2 max-w-sm text-sm leading-6 text-white/58">
                  No active scan. No fake threat data. Local engines report real
                  states only.
                </p>
              </div>
              <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-[#16C7A7]/14 text-2xl">
                ✓
              </div>
            </div>
          </div>

          <div className="mt-4 grid gap-3 sm:grid-cols-3">
            {scanOptions.map((option) => (
              <div
                key={option}
                className="rounded-2xl border border-white/10 bg-white/[0.035] p-4"
              >
                <p className="text-sm font-bold text-white">{option}</p>
                <p className="mt-2 text-xs leading-5 text-white/50">
                  Ready when started
                </p>
              </div>
            ))}
          </div>

          <div className="mt-4 grid gap-3 sm:grid-cols-2">
            {engines.map(([name, status]) => (
              <div
                key={name}
                className="grid gap-1 rounded-2xl border border-white/10 bg-white/[0.035] px-4 py-3 sm:flex sm:items-center sm:justify-between sm:gap-2"
              >
                <span className="text-sm font-semibold text-white/78">
                  {name}
                </span>
                <span className="text-xs font-bold text-[#16C7A7]">
                  {status}
                </span>
              </div>
            ))}
          </div>

          <div className="mt-4 rounded-2xl border border-white/10 bg-[#091A2E] p-4">
            <div className="flex items-center justify-between gap-4">
              <div>
                <p className="text-sm font-bold text-white">Threat review</p>
                <p className="mt-1 text-xs text-white/50">
                  No active scan. Review items appear only after real local
                  detections.
                </p>
              </div>
              <StatusBadge tone="muted">Empty state</StatusBadge>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
