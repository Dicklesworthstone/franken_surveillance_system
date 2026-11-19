import { imageMeta, imageBody } from "../../../lib/share-card";
export const dynamic = "force-static";
export const generateImageMetadata = () => imageMeta("motion-study", 630);
export default function Image() {
  return imageBody("motion-study", 630);
}
