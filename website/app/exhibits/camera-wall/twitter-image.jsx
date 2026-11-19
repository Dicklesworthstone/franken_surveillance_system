import { imageMeta, imageBody } from "../../../lib/share-card";
export const dynamic = "force-static";
export const generateImageMetadata = () => imageMeta("camera-wall", 600);
export default function Image() {
  return imageBody("camera-wall", 600);
}
