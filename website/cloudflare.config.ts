import { readFileSync } from "node:fs";
import { defineConfig } from "cf/config";

// Wrangler and cf deploy the same exported bytes to the same registered domain.
const wrangler = JSON.parse(
  readFileSync(new URL("./wrangler.jsonc", import.meta.url), "utf8"),
);

export default defineConfig({
  worker: {
    name: wrangler.name,
    compatibilityDate: wrangler.compatibility_date,
    workersDev: wrangler.workers_dev,
    previewUrls: wrangler.preview_urls,
    assets: { notFoundHandling: wrangler.assets.not_found_handling },
    domains: wrangler.routes
      .filter((route: { custom_domain?: boolean }) => route.custom_domain)
      .map((route: { pattern: string }) => route.pattern),
  },
});
