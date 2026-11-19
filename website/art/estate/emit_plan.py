"""Write public/estate/estate.json from plan.py.

    python3 -B website/art/estate/emit_plan.py
"""
import json
import pathlib
import sys

here = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(here))
import plan  # noqa: E402

out = here.parent.parent / "public" / "estate" / "estate.json"
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(json.dumps(plan.as_json(), indent=2) + "\n")
print("wrote", out)
