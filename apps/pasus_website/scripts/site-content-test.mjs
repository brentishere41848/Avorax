import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

const root = process.cwd();
const files = [];
function walk(dir) {
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry);
    const stat = statSync(path);
    if (stat.isDirectory()) walk(path);
    else if (/\.(tsx|ts|md|css)$/.test(path)) files.push(path);
  }
}
walk(join(root, "app"));
walk(join(root, "components"));
walk(join(root, "lib"));

const text = files.map((file) => readFileSync(file, "utf8")).join("\n").toLowerCase();
const forbidden = [
  "anti-cheat",
  "gaming protection",
  "fair play",
  "player",
  "match",
  "game setup",
  "player session",
  "match telemetry",
  "fake checkout",
  "buy now",
  "purchase license",
  "fake stripe",
  "license key generated",
  "certified by av-test",
  "certified by",
  "trusted by millions",
  "best antivirus",
  "guaranteed protection",
  "award winning",
  "100% protection",
  "perfect protection",
];
for (const phrase of forbidden) {
  if (text.includes(phrase)) {
    throw new Error(`Forbidden website phrase found: ${phrase}`);
  }
}
for (const route of ["app/page.tsx", "app/pricing/page.tsx", "app/download/page.tsx", "app/waitlist/page.tsx"]) {
  statSync(join(root, route));
}
for (const route of ["app/checkout", "app/success", "app/payment"]) {
  try {
    statSync(join(root, route));
    throw new Error(`Forbidden checkout/payment route exists: ${route}`);
  } catch (error) {
    if (error && error.code !== "ENOENT") throw error;
  }
}
for (const component of [
  "components/product-preview.tsx",
  "components/trust-strip.tsx",
  "components/quick-scan-section.tsx",
  "components/realtime-guard-section.tsx",
  "components/quarantine-recovery-section.tsx",
  "components/protection-stack-section.tsx",
  "components/final-cta.tsx",
]) {
  statSync(join(root, component));
}
const required = [
  "Anti-malware protection built for speed, control, and clarity.",
  "No fake threat data",
  "Coming soon",
  "Waitlist backend is not configured yet",
  "Preview build link not configured",
];
const originalText = files.map((file) => readFileSync(file, "utf8")).join("\n");
for (const phrase of required) {
  if (!originalText.includes(phrase)) {
    throw new Error(`Required website phrase missing: ${phrase}`);
  }
}
console.log("Pasus website content tests passed.");
