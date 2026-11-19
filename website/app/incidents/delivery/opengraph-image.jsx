import { imageMeta, imageBody } from "../../../lib/share-card";
export const dynamic = "force-static";
export const generateImageMetadata = () => imageMeta("delivery", 630);
export default function Image() {
  return imageBody("delivery", 630);
}
