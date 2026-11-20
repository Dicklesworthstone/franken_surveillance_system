export async function matchesDigest(blob, digest) {
  const hash = await crypto.subtle.digest("SHA-256", await blob.arrayBuffer());
  const hex = Array.from(new Uint8Array(hash), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
  return "sha256:" + hex === digest;
}

export async function readEvidenceReport(path, signal) {
  const object = /^\/night-evidence\/objects\/([a-f0-9]{64})\.json$/.exec(path);
  if (!object) throw Error("Invalid evidence object path");
  const response = await fetch(path, { signal });
  if (!response.ok) throw Error("Evidence report unavailable");
  const blob = await response.blob();
  if (!(await matchesDigest(blob, "sha256:" + object[1]))) {
    throw Error("Evidence report differs from its retained digest");
  }
  return JSON.parse(await blob.text());
}
