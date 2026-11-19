import { imageMeta, imageBody } from "../../../lib/share-card";
export const dynamic = "force-static";
export const generateImageMetadata = () => imageMeta("event-ledger", 630);
export default function Image() {
  return imageBody("event-ledger", 630);
}
