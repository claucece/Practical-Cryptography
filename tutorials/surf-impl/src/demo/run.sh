#!/usr/bin/env bash
# Fetch a page over SURF and open it in a browser.
#
# Runs the full round, then one resumed round per discovered asset, then opens
# the assembled page. Each round is its own pair of processes, as everywhere
# else in this tree, but the point here is the artifact rather than the
# timings: <outdir>/index.html is the origin's page with every attested asset
# served from disk and a banner recording what was fetched and what it cost.
#
# Usage: run_demo.sh --host example.com [--path /] [--assets N]
#                    [--mode true|masked] [--outdir DIR] [--build-dir PATH]
set -u
host=""
path="/"
max_assets=4
mode="true"
outdir="/tmp/surf_demo"
build_dir="$(pwd)"
timeout_s=300
extra=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host)       host="$2"; shift 2 ;;
    --path)       path="$2"; shift 2 ;;
    --assets)     max_assets="$2"; shift 2 ;;
    --mode)       mode="$2"; shift 2 ;;
    --outdir)     outdir="$2"; shift 2 ;;
    --build-dir)  build_dir="$2"; shift 2 ;;
    --timeout)    timeout_s="$2"; shift 2 ;;
    --allow-unclean-close) extra+=( --allow_unclean_close ); shift ;;
    -h|--help)    sed -n '2,14p' "${BASH_SOURCE[0]}" >&2; exit 2 ;;
    *)            echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

[[ -n "$host" ]] || { echo "--host is required" >&2; exit 2; }
case "$mode" in
  true)   surf_true=1 ;;
  masked) surf_true=0 ;;
  *)      echo "--mode must be 'true' or 'masked'" >&2; exit 2 ;;
esac

bin="${build_dir}/SurfDemo"
[[ -x "$bin" ]] || { echo "missing: $bin (run from build/, or --build-dir)" >&2; exit 1; }

# A stale outdir would leave old resources in the manifest and produce a page
# mixing two fetches.
rm -rf "$outdir" "${outdir}_handoff"
mkdir -p "$outdir/raw" "${outdir}_handoff"
handoff="${outdir}_handoff"

verifier_pid=""
cleanup() { [[ -n "$verifier_pid" ]] && kill "$verifier_pid" 2>/dev/null; }
trap 'cleanup; exit 130' INT TERM

port=9500
# round ROUND -> prover exit code
run_round() {
  local round="$1"
  port=$(( port + 1 ))

  ( cd "$build_dir" && exec env SURF_TRUE="$surf_true" "$bin" --is_verifier \
      --ip 127.0.0.1 -v "$port" --handoff "$handoff" --outdir "$outdir" \
      --accept_timeout_ms $(( timeout_s * 1000 )) ) > "$outdir/verifier.log" 2>&1 &
  verifier_pid=$!
  sleep 0.5

  local -a args=( --host "$host" -v "$port" --round "$round"
                  --handoff "$handoff" --outdir "$outdir"
                  --max_assets "$max_assets" "${extra[@]+"${extra[@]}"}" )
  # --open only on the full round: it renders a placeholder page and opens the
  # browser before preprocessing starts, and every later round just rewrites
  # index.html for the meta-refresh already running in that window.
  [[ "$round" == "full" ]] && args+=( --path "$path" --open )

  ( cd "$build_dir" && exec env SURF_TRUE="$surf_true" \
      timeout "$timeout_s" "$bin" "${args[@]}" )
  local rc=$?

  kill "$verifier_pid" 2>/dev/null
  wait "$verifier_pid" 2>/dev/null
  verifier_pid=""
  return $rc
}

echo "== SURF demo: https://${host}${path} (${mode} mode)"
echo "   a browser opens immediately and refreshes as each resource lands;"
echo "   each round preprocesses its circuits from scratch, ~20s per resource"
echo

echo "-- page"
run_round full || { echo "the initial fetch failed; see $outdir/verifier.log" >&2; exit 1; }

queued=$( [[ -f "$outdir/assets.tsv" ]] && grep -c . "$outdir/assets.tsv" || echo 0 )
for (( i = 1; i <= queued; i++ )); do
  echo "-- asset $i/$queued"
  run_round resumed
  rc=$?
  case $rc in
    0) ;;
    2) break ;;
    *) echo "asset $i failed (rc=$rc); assembling what we have" >&2
       ( cd "$build_dir" && exec env SURF_TRUE="$surf_true" "$bin" \
           --build_only --outdir "$outdir" --host "$host" )
       break ;;
  esac
done
trap - INT TERM

echo
if [[ -f "$outdir/index.html" ]]; then
  # The browser was opened by the full round and has been refreshing since;
  # the last round dropped the meta-refresh, so it is now showing the final
  # page. Nothing to open here.
  echo "== $outdir/index.html"
else
  echo "no page was assembled; see $outdir/verifier.log" >&2
  exit 1
fi
