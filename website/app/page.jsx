import Observatory from "../components/Observatory";
import { fieldData } from "../lib/field-data";
export default function Page() {
  return <Observatory field={fieldData()} />;
}
