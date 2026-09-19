#!/usr/bin/env bash
# Run MultiGetBench N times in each mode and keep each run's raw output.
# Here:
#
#   1. The verifier is its own process (--is_verifier),
#      One verifier per round.
#   2. The origin is optional. With --host the prover connects to a live origin
#      on :443 and no local --is_server is spawned at all.
#   3. An iteration is one full round plus a fixed number of resumed rounds
#      (--resumed, default 2), so every iteration is the same shape.
#
# Log names match what aggregate_e2e.py globs:
#   iterNN_<mode>_full_server.log
#   iterNNrKK_<mode>_resumed_server.log
# The rKK suffix keeps multiple resumed rounds per iteration from colliding;
# MODE_RE is a search, not a match, so the extra segment is accepted, and
# numeric_key sorts on (NN, KK).
#
# Usage: run_multiget.sh [-n ITERATIONS] [--modes masked|true|both]
#                        [--host HOST] [--path PATH] [--ip IP]
#                        [--resumed N] [--build-dir PATH] [--timeout SEC]
set -u
iterations=1
modes_arg="both"
host=""
ip="127.0.0.1"
path="/"
build_dir="$(pwd)"
timeout_s=300
resumed_rounds=2

while [[ $# -gt 0 ]]; do
  case "$1" in
    -n|--iterations) iterations="$2"; shift 2 ;;
    -m|--modes)      modes_arg="$2"; shift 2 ;;
    --host)          host="$2"; shift 2 ;;
    --path)          path="$2"; shift 2 ;;
    --ip)            ip="$2"; shift 2 ;;
    --resumed)       resumed_rounds="$2"; shift 2 ;;
    --build-dir)     build_dir="$2"; shift 2 ;;
    --timeout)       timeout_s="$2"; shift 2 ;;
    -h|--help)       sed -n '2,32p' "${BASH_SOURCE[0]}" >&2; exit 2 ;;
    *)               echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

case "$modes_arg" in
  both)   modes=(masked true) ;;
  masked) modes=(masked) ;;
  true)   modes=(true) ;;
  *)      echo "--modes must be 'masked', 'true' or 'both'" >&2; exit 2 ;;
esac

bin="${build_dir}/MultiGetBench"
if [[ ! -x "$bin" ]]; then
  echo "missing or non-executable: $bin" >&2
  echo "run this from the build directory, or pass --build-dir" >&2
  exit 1
fi

# TRUE mode needs the commit-variant Bristol circuit on disk before the first
# run; BristolFormat aborts on a missing path rather than reporting it.
if [[ " ${modes[*]} " == *" true "* ]]; then
  circuit="$(cd "${build_dir}/.." && pwd)/2pc/derive_gcm_verify_commit.txt"
  [[ -f "$circuit" ]] || echo "[runner] warning: $circuit not found; TRUE runs will abort" >&2
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

# How many assets the full round queued.
queue_len() { [[ -f "$1/assets.txt" ]] && grep -c . "$1/assets.txt" || echo 0; }

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

  # --host skips the local origin entirely and defaults to :443 with SNI.
  # --path only applies to the full round; resumed rounds read the queue.
  # --max_assets caps the queue at exactly the number of rounds we will run,
  # so a page with more assets does not leave a partly-consumed queue on disk.
  local -a prover_args=( -v "$vport" --round "$round" --handoff "$handoff"
                         --max_assets "$resumed_rounds" )
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

  # Mode is the inner loop so both modes are sampled under near-identical
  # machine conditions; masked first, since a TRUE failure then cannot be
  # confused with a bad build.
  for mode_idx in "${!modes[@]}"; do
    mode="${modes[$mode_idx]}"
    [[ "$mode" == "true" ]] && surf_true=1 || surf_true=0

    ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    tag="${itag}_${mode}"
    echo "[runner] iteration ${iter}/${iterations} ${mode}"

    # Separate handoff per mode: a resumed round must replay a ticket minted by
    # a full round in the same mode, and PSK material must not cross origins.
    handoff="${log_dir}/${tag}_handoff"
    mkdir -p "$handoff"

    # Distinct ports per iteration and mode so a lingering TIME_WAIT cannot
    # collide with the next listener. One block of (2 + resumed_rounds) ports.
    base=$(( 20000 + (iter * 2 + mode_idx) * (resumed_rounds + 2) ))
    sport=$(( base ))
    vport_full=$(( base + 1 ))

    # Local origin only. It stays up for the whole mode-iteration and serves
    # every round; the fixed ticket key lets it decrypt tickets minted by an
    # earlier round's process.
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
    queued="$(queue_len "$handoff")"
    echo "ok (${queued} asset(s) queued)"

    # Every iteration runs the same number of resumed rounds, so the aggregator
    # sees one rNN group per round with one sample per iteration. A page with
    # too few assets cannot produce that, so it is an error rather than a
    # silently shorter chain that would skew the rNN groups.
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
      printf '  resumed %d/%d ... ' "$k" "$resumed_rounds"
      run_round resumed $(( vport_full + k )) "$sport" "$handoff" "$surf_true" \
        "${log_dir}/${rtag}_resumed_server.log" \
        "${log_dir}/${rtag}_resumed_prover.log"
      rc=$?
      case $rc in
        0)   echo "ok"; resumed_ok=$(( resumed_ok + 1 )) ;;
        # rc=2 here means the cursor did not advance as expected: the queue was
        # long enough at the start of the iteration, so this is a bug, not an
        # ordinary end-of-queue.
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
  echo "[runner] ${mode}: ${ok_count[$mode]}/${iterations} iteration(s) fully ok"
done
echo "[runner] logs:    ${log_dir}"
echo "[runner] summary: ${summary}"
echo "[runner] aggregate: ./aggregate_e2e.py ${log_dir}"
