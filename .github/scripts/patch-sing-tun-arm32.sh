#!/usr/bin/env bash
set -euo pipefail

module="github.com/sagernet/sing-tun"
module_dir="$(go mod download -json "$module" | python3 -c 'import json,sys; print(json.load(sys.stdin)["Dir"])')"
target="$module_dir/redirect_route_linux.go"

if [[ ! -f "$target" ]]; then
  echo "ERROR: sing-tun Linux redirect source not found: $target" >&2
  exit 1
fi

python3 - "$target" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
source = path.read_text()
old = """\tfor {
\t\tr.redirectRouteTableIndex = int(rand.Uint32())
\t\tif r.redirectRouteTableIndex == r.tunOptions.IPRoute2TableIndex {
\t\t\tcontinue
\t\t}
\t\trouteList, fErr := netlink.RouteListFiltered(netlink.FAMILY_ALL,
\t\t\t&netlink.Route{Table: r.redirectRouteTableIndex},
\t\t\tnetlink.RT_FILTER_TABLE)
\t\tif len(routeList) == 0 || fErr != nil {
\t\t\tbreak
\t\t}
\t}
"""
new = """\tfor {
\t\tcandidate := int(rand.Uint32() & 0x7fffffff)
\t\tif candidate <= 255 || candidate == r.tunOptions.IPRoute2TableIndex {
\t\t\tcontinue
\t\t}
\t\trouteList, fErr := netlink.RouteListFiltered(netlink.FAMILY_ALL,
\t\t\t&netlink.Route{Table: candidate},
\t\t\tnetlink.RT_FILTER_TABLE)
\t\tif fErr != nil {
\t\t\treturn E.Cause(fErr, "check redirect route table")
\t\t}
\t\tif len(routeList) == 0 {
\t\t\tr.redirectRouteTableIndex = candidate
\t\t\tbreak
\t\t}
\t}
"""
if source.count(old) != 1:
    raise SystemExit(
        "ERROR: expected exactly one unpatched ARM32-vulnerable route-table "
        "selection loop; refusing to modify an unknown sing-tun source."
    )
path.chmod(path.stat().st_mode | 0o200)
path.write_text(source.replace(old, new, 1))
print(f"Patched ARM32-safe redirect route-table selection: {path}")
PY
