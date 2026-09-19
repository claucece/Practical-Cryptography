#!/usr/bin/env bash
# Run MultiGetH2Bench N times in each mode and keep each run's raw output.
#
# The log names:
#   iterNN_<mode>_full_server.log
#   iterNN_<mode>_resumed_server.log
#
# Usage: run_multigeth2.sh [-n ITERATIONS] [--modes masked|true|both]
#                          [--host HOST] [--path PATH] [--ip IP]
#                          [--max-assets N] [--build-dir PATH] [--timeout SEC]
set -u
iterations=1
modes_arg="both"
host=""
ip="127.0.0.1"
path="/"
build_dir="$(pwd)"
timeout_s=300
max_assets=2

while [[ $# -gt 0 ]]; do
  case "$1" in
    -n|--iterations) iterations="$2"; shift 2 ;;
    -m|--modes)      modes_arg="$2"; shift 2 ;;
    --host)          host="$2"; shift 2 ;;
    --path)          path="$2"; shift 2 ;;
    --ip)            ip="$2"; shift 2 ;;
    --max-assets)    max_assets="$2"; shift 2 ;;
    --build-dir)     build_dir="$2"; shift 2 ;;
    --timeout)       timeout_s="$2"; shift 2 ;;
    -h|--help)       sed -n '2,26p' "${BASH_SOURCE[0]}" >&2; exit 2 ;;
    *)               echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

case "$modes_arg" in
  both)   modes=(masked true) ;;
  masked) modes=(masked) ;;
  true)   modes=(true) ;;
  *)      echo "--modes must be 'masked', 'true' or 'both'" >&2; exit 2 ;;
esac

bin="${build_dir}/MultiGetH2Bench"
if [[ ! -x "$bin" ]]; then
  echo "missing or non-executable: $bin" >&2
  echo "run this from the build directory, or pass --build-dir" >&2
  exit 1
fi

data_dir="$(cd "${build_dir}/.." && pwd)/data"
run_id="$(date -u +%Y%m%dT%H%M%SZ)"
log_dir="${data_dir}/${run_id}"
mkdir -p "$log_dir" || { echo "cannot create $log_dir" >&2; exit 1; }
summary="${log_dir}/summary.txt"
: > "$summary"

target="${host:-$ip (local origin)}"
echo "[runner] ${iterations} iteration(s) x {${modes[*]}} against ${target}${path}"
echo "[runner] logs in ${log_dir}"

origin_pid=""; verifier_pid=""; prover_pid=""
cleanup() {
  for p in "$prover_pid" "$verifier_pid" "$origin_pid"; do
    [[ -n "$p" ]] && kill "$p" 2>/dev/null
  done
}
trap 'cleanup; exit 130' INT TERM

# run_round ROUND VPORT SPORT HANDOFF SURF_TRUE SERVER_LOG PROVER_LOG
# Returns the prover's exit code, or 124 on timeout.
run_round() {
  local round="$1" vport="$2" sport="$3" handoff="$4" surf_true="$5"
  local server_log="$6" prover_log="$7"

  ( cd "$build_dir" && exec env SURF_TRUE="$surf_true" "$bin" --is_verifier \
      --ip "$ip" -v "$vport" --round "$round" --handoff "$handoff" \
      --accept_timeout_ms $(( timeout_s * 1000 )) ) > "$server_log" 2>&1 &
  verifier_pid=$!
  sleep 0.3
  if ! kill -0 "$verifier_pid" 2>/dev/null; then
    verifier_pid=""
    echo "    verifier died immediately; see $server_log" >&2
    return 1
  fi

  local -a prover_args=( -v "$vport" --round "$round" --handoff "$handoff"
                         --max_assets "$max_assets" )
  if [[ -n "$host" ]]; then
    prover_args+=( --host "$host" )
  else
    prover_args+=( --ip "$ip" -p "$sport" )
  fi
  [[ "$round" == "full" ]] && prover_args+=( -r "$path" )

  ( cd "$build_dir" && exec env SURF_TRUE="$surf_true" "$bin" \
      "${prover_args[@]}" ) > "$prover_log" 2>&1 &
  prover_pid=$!

  local timed_out=0 waited
  for (( waited = 0; waited < timeout_s; waited++ )); do
    kill -0 "$prover_pid" 2>/dev/null || break
    sleep 1
  done
  if kill -0 "$prover_pid" 2>/dev/null; then
    timed_out=1
    kill "$prover_pid" 2>/dev/null
  fi

  wait "$prover_pid" 2>/dev/null; local prover_rc=$?
  kill "$verifier_pid" 2>/dev/null
  wait "$verifier_pid" 2>/dev/null
  prover_pid=""; verifier_pid=""

  (( timed_out )) && return 124
  return "$prover_rc"
}

declare -A ok_count
for mode in "${modes[@]}"; do ok_count["$mode"]=0; done

for iter in $(seq 1 "$iterations"); do
  itag="iter$(printf '%02d' "$iter")"

  for mode_idx in "${!modes[@]}"; do
    mode="${modes[$mode_idx]}"
    [[ "$mode" == "true" ]] && surf_true=1 || surf_true=0

    ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    tag="${itag}_${mode}"
    echo "[runner] iteration ${iter}/${iterations} ${mode}"

    handoff="${log_dir}/${tag}_handoff"
    mkdir -p "$handoff"

    base=$(( 20000 + (iter * 2 + mode_idx) * 4 ))
    sport=$(( base ))
    vport_full=$(( base + 1 ))
    vport_res=$(( base + 2 ))

    if [[ -z "$host" ]]; then
      ( cd "$build_dir" && exec "$bin" --is_server --ip "$ip" -p "$sport" \
          --accept_timeout_ms $(( timeout_s * 1000 )) ) \
          > "${log_dir}/${tag}_origin.log" 2>&1 &
      origin_pid=$!
      sleep 0.3
    fi

    printf '  full ... '
    run_round full "$vport_full" "$sport" "$handoff" "$surf_true" \
      "${log_dir}/${tag}_full_server.log" "${log_dir}/${tag}_full_prover.log"
    rc=$?
    if (( rc != 0 )); then
      [[ $rc -eq 124 ]] && echo "TIMEOUT (${timeout_s}s)" || echo "FAILED (rc=$rc)"
      printf '%2d  %-6s  %s  full_%s\n' "$iter" "$mode" "$ts" \
        "$( (( rc == 124 )) && echo timeout || echo failed )" >> "$summary"
      [[ -n "$origin_pid" ]] && { kill "$origin_pid" 2>/dev/null; origin_pid=""; }
      continue
    fi
    queued=$( [[ -f "$handoff/assets.txt" ]] && grep -c . "$handoff/assets.txt" || echo 0 )
    echo "ok (${queued} asset(s) queued)"

    printf '  resumed (%d stream(s)) ... ' "$queued"
    run_round resumed "$vport_res" "$sport" "$handoff" "$surf_true" \
      "${log_dir}/${tag}_resumed_server.log" \
      "${log_dir}/${tag}_resumed_prover.log"
    rc=$?

    [[ -n "$origin_pid" ]] && { kill "$origin_pid" 2>/dev/null; wait "$origin_pid" 2>/dev/null; origin_pid=""; }

    case $rc in
      0)
        echo "ok"
        ok_count["$mode"]=$(( ${ok_count["$mode"]} + 1 ))
        printf '%2d  %-6s  %s  ok  %d stream(s)\n' "$iter" "$mode" "$ts" \
          "$queued" >> "$summary"
        ;;
      2)
        echo "no assets to fetch"
        rm -f "${log_dir}/${tag}"_resumed_*.log
        printf '%2d  %-6s  %s  no_assets\n' "$iter" "$mode" "$ts" >> "$summary"
        ;;
      124)
        echo "TIMEOUT (${timeout_s}s)"
        printf '%2d  %-6s  %s  resumed_timeout\n' "$iter" "$mode" "$ts" >> "$summary"
        ;;
      *)
        echo "FAILED (rc=$rc)"
        printf '%2d  %-6s  %s  resumed_failed\n' "$iter" "$mode" "$ts" >> "$summary"
        ;;
    esac
  done
done
trap - INT TERM

echo
for mode in "${modes[@]}"; do
  echo "[runner] ${mode}: ${ok_count[$mode]}/${iterations} iteration(s) ok"
done
echo "[runner] logs:    ${log_dir}"
echo "[runner] summary: ${summary}"
echo "[runner] aggregate: ./aggregate_e2e.py ${log_dir}"
