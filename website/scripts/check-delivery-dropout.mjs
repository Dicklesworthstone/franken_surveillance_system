import { fileURLToPath } from "node:url";
import { readDeliveryDropout } from "../lib/watch/delivery-dropout.mjs";

const dir = process.argv[2] ?? fileURLToPath(new URL("../public/watch/delivery-dropout/", import.meta.url));
const scene = process.argv[3] ?? fileURLToPath(new URL("../public/watch/intrusion/scene.json", import.meta.url));
const measured = readDeliveryDropout(dir, scene);
console.log("Verified", measured.complete.samples, "complete frames,", measured.dropout.samples,
  "surviving byte-identical samples, gap", measured.dropout.gaps, "and",
  measured.dropout.witnesses.length, "retained dropout coverage witnesses.");
