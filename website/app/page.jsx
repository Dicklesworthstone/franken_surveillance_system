import Observatory from "../components/Observatory";
import { fieldData } from "../lib/field-data";
export const metadata = {
  alternates: { canonical: "/" },
  openGraph: { url: "/", type: "website" },
};
export default function Page() {
  return <Observatory field={fieldData()} />;
}
