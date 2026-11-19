import { imageMeta, imageBody } from "../../../lib/share-card";
export const dynamic = "force-static";
export const generateImageMetadata = () => imageMeta("delivery", 600);
export default function Image() {
  return imageBody("delivery", 600);
}
