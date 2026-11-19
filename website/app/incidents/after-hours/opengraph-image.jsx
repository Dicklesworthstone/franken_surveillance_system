import { imageMeta, imageBody } from "../../../lib/share-card";
export const dynamic = "force-static";
export const generateImageMetadata = () => imageMeta("after-hours", 630);
export default function Image() {
  return imageBody("after-hours", 630);
}
