import type { MetadataRoute } from "next";
import { siteConfig } from "../lib/site-config";

const routes = ["", "/product", "/protection", "/pricing", "/download", "/waitlist", "/privacy", "/terms", "/roadmap"];

export default function sitemap(): MetadataRoute.Sitemap {
  return routes.map((route) => ({
    url: `${siteConfig.url}${route}`,
    lastModified: new Date(),
  }));
}
