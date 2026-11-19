import { imageMeta, imageBody } from "../../../lib/share-card";
export const dynamic = "force-static";
export const generateImageMetadata = () => imageMeta("after-hours", 600);
export default function Image() {
  return imageBody("after-hours", 600);
}
