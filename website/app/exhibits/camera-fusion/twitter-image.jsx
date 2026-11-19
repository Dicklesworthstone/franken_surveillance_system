import { imageMeta, imageBody } from "../../../lib/share-card";
export const dynamic = "force-static";
export const generateImageMetadata = () => imageMeta("camera-fusion", 600);
export default function Image() {
  return imageBody("camera-fusion", 600);
}
