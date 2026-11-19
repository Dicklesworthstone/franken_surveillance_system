import { imageMeta, imageBody } from "../../../lib/share-card";
export const dynamic = "force-static";
export const generateImageMetadata = () => imageMeta("poster-room", 630);
export default function Image() {
  return imageBody("poster-room", 630);
}
