import { imageMeta, imageBody } from "../../../lib/share-card";
export const dynamic = "force-static";
export const generateImageMetadata = () => imageMeta("digital-twin", 630);
export default function Image() {
  return imageBody("digital-twin", 630);
}
