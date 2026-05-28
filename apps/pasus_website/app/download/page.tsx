import { DownloadCard, type ReleaseAsset } from "../../components/download-card";
import { siteConfig } from "../../lib/site-config";

export const dynamic = "force-dynamic";

async function getAssets(): Promise<ReleaseAsset[]> {
  try {
    const response = await fetch(
      `https://api.github.com/repos/${siteConfig.repoOwner}/${siteConfig.repoName}/releases/latest`,
      { headers: { "User-Agent": "Pasus-Website" }, cache: "no-store" },
    );
    if (!response.ok) return [];
    const release = await response.json();
    if (!Array.isArray(release.assets)) return [];
    return release.assets
      .filter((asset: { name?: string; browser_download_url?: string }) =>
        Boolean(asset.name && asset.browser_download_url),
      )
      .map((asset: { name: string; browser_download_url: string }) => ({
        name: asset.name,
        url: asset.browser_download_url,
      }));
  } catch {
    return [];
  }
}

export default async function DownloadPage() {
  const assets = await getAssets();
  return (
    <section className="section-pad">
      <div className="container grid gap-10 lg:grid-cols-[0.85fr_1.15fr]">
        <div>
          <div className="pill bg-[#F5A524]/12 text-[#8A5A00]">Preview build</div>
          <h1 className="mt-6 text-[42px] font-extrabold leading-[1.02] tracking-[-0.05em] md:text-6xl">Download Pasus preview.</h1>
          <p className="mt-5 leading-8 text-[#5B6678]">
            Preview installers are for testing. Keep Microsoft Defender or your existing antivirus enabled.
          </p>
          <ul className="mt-8 space-y-3 text-[#5B6678]">
            <li>• Windows preview installer</li>
            <li>• MSI and EXE setup when release assets exist</li>
            <li>• Known limitations documented before production use</li>
          </ul>
        </div>
        <DownloadCard assets={assets} />
      </div>
    </section>
  );
}
