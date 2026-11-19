import { imageMeta, imageBody } from "../../../lib/share-card";
export const dynamic = "force-static";
export const generateImageMetadata = () => imageMeta("owner-response", 600);
export default function Image() {
  return imageBody("owner-response", 600);
}
