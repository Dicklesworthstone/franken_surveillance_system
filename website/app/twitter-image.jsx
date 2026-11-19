import { imageBody, imageMeta } from "../lib/share-card";
export const dynamic = "force-static";
export async function generateImageMetadata() {
  return imageMeta("home", 600);
}
export default async function Image() {
  return imageBody("home", 600);
}
