import { imageMeta, imageBody } from "../../../lib/share-card";
export const dynamic = "force-static";
export const generateImageMetadata = () => imageMeta("agent-console", 630);
export default function Image() {
  return imageBody("agent-console", 630);
}
