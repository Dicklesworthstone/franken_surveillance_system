import { imageBody, imageMeta } from "../lib/share-card";
export const dynamic = "force-static";
export async function generateImageMetadata() {
  return imageMeta("home", 630);
}
export default async function Image() {
  return imageBody("home", 630);
}
