#!/usr/bin/env python3
"""Generate gf_summary.json from gf pattern output files."""
import json, os, sys, glob

run_dir = sys.argv[1] if len(sys.argv) > 1 else "."

summary = {}
for f in sorted(glob.glob(f"{run_dir}/gf_*.txt")):
    pattern = os.path.basename(f).replace("gf_", "").replace(".txt", "")
    try:
        with open(f) as fh:
            urls = [l.strip() for l in fh if l.strip()]
        if urls:
            summary[pattern] = {"count": len(urls), "top_urls": urls[:5]}
    except Exception:
        pass

result = {
    "patterns": summary,
    "total_matches": sum(v["count"] for v in summary.values()),
}

outfile = f"{run_dir}/gf_summary.json"
with open(outfile, "w") as out:
    json.dump(result, out, indent=2)

print(result["total_matches"])
