import { imageMeta, imageBody } from "../../../lib/share-card";
export const dynamic = "force-static";
export const generateImageMetadata = () => imageMeta("field-method", 630);
export default function Image() {
  return imageBody("field-method", 630);
}
