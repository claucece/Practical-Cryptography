#!/usr/bin/env bash
# Prover half of a split-host MultiGetBench run. Runs on the machine that plays
# C; run_multiget_verifier.sh runs on the machine that plays V.
#
# Start the VERIFIER side first. A verifier with no prover blocks in accept()
# until its --timeout, which is harmless; a prover with no verifier gets
# ECONNREFUSED and fails the round.
#
# Both sides must be given identical -n, --modes, --resumed and --port-base:
# that is the only thing keeping them in step.
#
# The origin is either local to this host (default, spawned with --is_server)
# or a live server named with --host, in which case nothing is spawned and the
# prover connects to :443 with SNI.
#
# Handoff: this side holds the session ticket, the prover's PSK share and the
# asset queue. It is local to this host; the verifier keeps its own share
# separately and the two directories must not be shared.
#
# Usage: run_multiget_prover.sh --verifier-ip IP [-n ITERATIONS]
#                               [--modes masked|true|both] [--resumed N]
#                               [--port-base N] [--host HOST] [--path PATH]
#                               [--ip ORIGIN_IP] [--build-dir PATH]
#                               [--timeout SEC] [--wait SEC]
set -u

iterations=1
modes_arg="both"
verifier_ip=""
host=""
ip="127.0.0.1"
path="/"
build_dir="$(pwd)"
timeout_s=600
resumed_rounds=2
port_base=20000
start_wait=2

while [[ $# -gt 0 ]]; do
  case "$1" in
    -n|--iterations)  iterations="$2"; shift 2 ;;
    -m|--modes)       modes_arg="$2"; shift 2 ;;
    --verifier-ip)    verifier_ip="$2"; shift 2 ;;
    --host)           host="$2"; shift 2 ;;
    --path)           path="$2"; shift 2 ;;
    --ip)             ip="$2"; shift 2 ;;
    --resumed)        resumed_rounds="$2"; shift 2 ;;
    --port-base)      port_base="$2"; shift 2 ;;
    --build-dir)      build_dir="$2"; shift 2 ;;
    --timeout)        timeout_s="$2"; shift 2 ;;
    --wait)           start_wait="$2"; shift 2 ;;
    -h|--help)        sed -n '2,27p' "${BASH_SOURCE[0]}" >&2; exit 2 ;;
    *)                echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "$verifier_ip" ]]; then
  echo "--verifier-ip is required: the address the verifier side bound with --ip" >&2
  exit 2
fi

case "$modes_arg" in
  both)   modes=(masked true) ;;
  masked) modes=(masked) ;;
  true)   modes=(true) ;;
  *)      echo "--modes must be 'masked', 'true' or 'both'" >&2; exit 2 ;;
esac

bin="${build_dir}/MultiGetBench"
if [[ ! -x "$bin" ]]; then
  echo "missing or non-executable: $bin" >&2
  exit 1
fi

if [[ " ${modes[*]} " == *" true "* ]]; then
  circuit="$(cd "${build_dir}/.." && pwd)/2pc/key-derivation/derive_gcm_verify_commit.txt"
  [[ -f "$circuit" ]] || echo "[prover] warning: $circuit not found; TRUE runs will abort" >&2
fi

data_dir="$(cd "${build_dir}/.." && pwd)/data"
run_id="$(date -u +%Y%m%dT%H%M%SZ)"
log_dir="${data_dir}/${run_id}"
mkdir -p "$log_dir" || { echo "cannot create $log_dir" >&2; exit 1; }
summary="${log_dir}/summary.txt"
: > "$summary"

target="${host:-$ip (local origin)}"
echo "[prover] verifier at ${verifier_ip}, ports from ${port_base}"
echo "[prover] ${iterations} iteration(s) x {${modes[*]}} against ${target}${path}"
echo "[prover] logs in ${log_dir}"

# A round-trip to the verifier, for the record. The MPC is round-heavy, so this
# number is the single best predictor of the online phases.
if command -v ping >/dev/null 2>&1; then
  rtt="$(ping -c 3 -q "$verifier_ip" 2>/dev/null | awk -F'/' '/^r.*avg/ {print $5}')"
  [[ -n "${rtt:-}" ]] && echo "[prover] verifier RTT ~${rtt} ms"
fi

if (( start_wait > 0 )); then
  echo "[prover] waiting ${start_wait}s for the verifier to come up"
  sleep "$start_wait"
fi

origin_pid=""; prover_pid=""
cleanup() {
  for p in "$prover_pid" "$origin_pid"; do
    [[ -n "$p" ]] && kill "$p" 2>/dev/null
  done
}
trap 'cleanup; exit 130' INT TERM

queue_len() { [[ -f "$1/assets.txt" ]] && grep -c . "$1/assets.txt" || echo 0; }

# One prover process, one round. Returns its exit code, or 124 on timeout.
run_prover() {
  local round="$1" vport="$2" sport="$3" handoff="$4" surf_true="$5"
  local prover_log="$6"

  local -a args=( --verifier_ip "$verifier_ip" -v "$vport"
                  --round "$round" --handoff "$handoff"
                  --max_assets "$resumed_rounds" )
  if [[ -n "$host" ]]; then
    args+=( --host "$host" )
  else
    args+=( --ip "$ip" -p "$sport" )
  fi
  [[ "$round" == "full" ]] && args+=( -r "$path" )

  ( cd "$build_dir" && exec env SURF_TRUE="$surf_true" "$bin" "${args[@]}" ) \
      > "$prover_log" 2>&1 &
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

  wait "$prover_pid" 2>/dev/null; local rc=$?
  prover_pid=""

  (( timed_out )) && return 124
  return "$rc"
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
    echo "[prover] iteration ${iter}/${iterations} ${mode}"

    handoff="${log_dir}/${tag}_handoff"
    mkdir -p "$handoff"

    # MUST match the verifier's formula exactly.
    base=$(( port_base + (iter * 2 + mode_idx) * (resumed_rounds + 2) ))
    sport=$(( base ))
    vport_full=$(( base + 1 ))

    # Local origin, on this host. Stays up for the whole mode-iteration; the
    # fixed ticket key lets it decrypt tickets minted by an earlier round's
    # process.
    if [[ -z "$host" ]]; then
      ( cd "$build_dir" && exec "$bin" --is_server --ip "$ip" -p "$sport" \
          --accept_timeout_ms $(( timeout_s * 1000 )) ) \
          > "${log_dir}/${tag}_origin.log" 2>&1 &
      origin_pid=$!
      sleep 0.3
    fi

    printf '  full (verifier port %d) ... ' "$vport_full"
    run_prover full "$vport_full" "$sport" "$handoff" "$surf_true" \
      "${log_dir}/${tag}_full_prover.log"
    rc=$?
    if (( rc != 0 )); then
      [[ $rc -eq 124 ]] && echo "TIMEOUT (${timeout_s}s)" || echo "FAILED (rc=$rc)"
      printf '%2d  %-6s  %s  full_%s\n' "$iter" "$mode" "$ts" \
        "$( (( rc == 124 )) && echo timeout || echo failed )" >> "$summary"
      [[ -n "$origin_pid" ]] && { kill "$origin_pid" 2>/dev/null; origin_pid=""; }
      echo "  NOTE: the verifier side is now one round ahead. Stop both sides" >&2
      echo "        and restart them together before trusting later rounds." >&2
      continue
    fi
    queued="$(queue_len "$handoff")"
    echo "ok (${queued} asset(s) queued)"

    if (( queued < resumed_rounds )); then
      echo "  only ${queued} asset(s) queued, need ${resumed_rounds}; skipping resumed rounds"
      printf '%2d  %-6s  %s  short_queue  %d<%d\n' "$iter" "$mode" "$ts" \
        "$queued" "$resumed_rounds" >> "$summary"
      [[ -n "$origin_pid" ]] && { kill "$origin_pid" 2>/dev/null; origin_pid=""; }
      continue
    fi

    resumed_ok=0; resumed_fail=0
    for (( k = 1; k <= resumed_rounds; k++ )); do
      rtag="${itag}r$(printf '%02d' "$k")_${mode}"
      vport=$(( vport_full + k ))
      printf '  resumed %d/%d (verifier port %d) ... ' "$k" "$resumed_rounds" "$vport"
      run_prover resumed "$vport" "$sport" "$handoff" "$surf_true" \
        "${log_dir}/${rtag}_resumed_prover.log"
      rc=$?
      case $rc in
        0)   echo "ok"; resumed_ok=$(( resumed_ok + 1 )) ;;
        2)   echo "FAILED (queue exhausted early at round $k of $resumed_rounds)"
             resumed_fail=$(( resumed_fail + 1 )); break ;;
        124) echo "TIMEOUT (${timeout_s}s)"; resumed_fail=$(( resumed_fail + 1 )); break ;;
        *)   echo "FAILED (rc=$rc)"; resumed_fail=$(( resumed_fail + 1 )); break ;;
      esac
    done

    [[ -n "$origin_pid" ]] && { kill "$origin_pid" 2>/dev/null; wait "$origin_pid" 2>/dev/null; origin_pid=""; }

    if (( resumed_fail == 0 )); then
      ok_count["$mode"]=$(( ${ok_count["$mode"]} + 1 ))
      printf '%2d  %-6s  %s  ok  full+%d resumed\n' "$iter" "$mode" "$ts" \
        "$resumed_ok" >> "$summary"
    else
      printf '%2d  %-6s  %s  resumed_failed  after %d ok\n' "$iter" "$mode" \
        "$ts" "$resumed_ok" >> "$summary"
    fi
  done
done
trap - INT TERM

echo
for mode in "${modes[@]}"; do
  echo "[prover] ${mode}: ${ok_count[$mode]}/${iterations} iteration(s) fully ok"
done
echo "[prover] logs:    ${log_dir}"
echo "[prover] summary: ${summary}"
echo "[prover] the parseable *_server.log files are on the VERIFIER host"
