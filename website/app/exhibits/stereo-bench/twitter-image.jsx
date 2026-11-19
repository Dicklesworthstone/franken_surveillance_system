import { imageMeta, imageBody } from "../../../lib/share-card";
export const dynamic = "force-static";
export const generateImageMetadata = () => imageMeta("stereo-bench", 600);
export default function Image() {
  return imageBody("stereo-bench", 600);
}
