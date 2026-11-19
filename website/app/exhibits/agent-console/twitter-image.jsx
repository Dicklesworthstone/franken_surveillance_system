import { imageMeta, imageBody } from "../../../lib/share-card";
export const dynamic = "force-static";
export const generateImageMetadata = () => imageMeta("agent-console", 600);
export default function Image() {
  return imageBody("agent-console", 600);
}
