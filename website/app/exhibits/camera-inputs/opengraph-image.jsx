import { imageMeta, imageBody } from "../../../lib/share-card";
export const dynamic = "force-static";
export const generateImageMetadata = () => imageMeta("camera-inputs", 630);
export default function Image() {
  return imageBody("camera-inputs", 630);
}
