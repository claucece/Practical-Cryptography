#!/usr/bin/env bash
# Browse a real site over SURF in true mode.
#
# Usage: run_proxy.sh --host example.com [--port 8080] [--build-dir PATH]
#
#   --stage   rewrite stylesheet links to be non-render-blocking, so the page
#             paints bare and restyles when the CSS lands. Edits the origin's
#             HTML; disclosed on /__surf.
set -u

host=""
browser_port=8080
verifier_port=9500
build_dir="$(pwd)"
timeout_s=600
extra=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host)           host="$2"; shift 2 ;;
    --port)           browser_port="$2"; shift 2 ;;
    --verifier-port)  verifier_port="$2"; shift 2 ;;
    --build-dir)      build_dir="$2"; shift 2 ;;
    --timeout)        timeout_s="$2"; shift 2 ;;
    --fetch-favicon)  extra+=( --fetch_favicon ); shift ;;
    --no-csp)         extra+=( --no_csp ); shift ;;
    --stage)          extra+=( --stage ); shift ;;
    -h|--help)        sed -n '2,15p' "${BASH_SOURCE[0]}" >&2; exit 2 ;;
    *)                echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

[[ -n "$host" ]] || { echo "--host is required" >&2; exit 2; }

bin="${build_dir}/SurfProxy"
[[ -x "$bin" ]] || { echo "missing: $bin (run from build/, or --build-dir)" >&2; exit 1; }

log_dir="${TMPDIR:-/tmp}/surf_proxy"
mkdir -p "$log_dir"
vlog="${log_dir}/verifier.$(date +%s).log"

verifier_pid=""
cleanup() {
  if [[ -n "$verifier_pid" ]]; then
    kill "$verifier_pid" 2>/dev/null
    wait "$verifier_pid" 2>/dev/null
  fi
}
trap 'cleanup; exit 130' INT TERM

echo "== SURF proxy: https://${host} (true mode)"
echo "   verifier log: $vlog"
echo "   one SURF connection per browser request, ~15s each"
echo

( cd "$build_dir" && exec env SURF_TRUE=1 "$bin" --is_verifier \
    --ip 127.0.0.1 -v "$verifier_port" \
    --accept_timeout_ms $(( timeout_s * 1000 )) ) > "$vlog" 2>&1 &
verifier_pid=$!

# Give the verifier a moment to bind before the first round races it.
for _ in $(seq 20); do
  if ! kill -0 "$verifier_pid" 2>/dev/null; then
    echo "the verifier exited immediately; see $vlog" >&2
    exit 1
  fi
  grep -q "\[Verifier\] port=" "$vlog" 2>/dev/null && break
  sleep 0.25
done

( cd "$build_dir" && exec env SURF_TRUE=1 "$bin" \
    --host "$host" -v "$verifier_port" -b "$browser_port" --open \
    "${extra[@]+"${extra[@]}"}" )
rc=$?

cleanup
trap - INT TERM

if (( rc != 0 )); then
  echo "the prover exited with $rc; see $vlog" >&2
fi
exit $rc
