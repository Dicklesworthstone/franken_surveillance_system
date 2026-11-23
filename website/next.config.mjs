export default {
  // A second dev server can run beside the main one by naming its own build directory.
  distDir: process.env.FSS_NEXT_DIST || ".next",
  // The repository has its own AGENTS.md; Next must not write a second one here.
  agentRules: false,
  output: "export",
  trailingSlash: true,
  devIndicators: false,
  images: { unoptimized: true },
  experimental: { cpus: 6 },
};
