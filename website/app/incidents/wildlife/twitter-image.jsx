import { imageMeta, imageBody } from "../../../lib/share-card";
export const dynamic = "force-static";
export const generateImageMetadata = () => imageMeta("wildlife", 600);
export default function Image() {
  return imageBody("wildlife", 600);
}
