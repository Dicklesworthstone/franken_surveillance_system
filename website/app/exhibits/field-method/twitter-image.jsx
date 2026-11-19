import { imageMeta, imageBody } from "../../../lib/share-card";
export const dynamic = "force-static";
export const generateImageMetadata = () => imageMeta("field-method", 600);
export default function Image() {
  return imageBody("field-method", 600);
}
