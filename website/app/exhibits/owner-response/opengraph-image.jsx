import { imageMeta, imageBody } from "../../../lib/share-card";
export const dynamic = "force-static";
export const generateImageMetadata = () => imageMeta("owner-response", 630);
export default function Image() {
  return imageBody("owner-response", 630);
}
