import { imageMeta, imageBody } from "../../../lib/share-card";
export const dynamic = "force-static";
export const generateImageMetadata = () => imageMeta("event-ledger", 600);
export default function Image() {
  return imageBody("event-ledger", 600);
}
