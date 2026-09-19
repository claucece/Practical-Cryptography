#!/usr/bin/env bash
# Run E2EBench N times in each mode and keep each run's raw output.
#
# Each iteration launches two process pairs per mode: one for the full round
# and one for the resumed round, with a handoff directory carrying the session
# ticket and PSK shares between them. Each round's online phases are free of
# the first-touch page faults that a second round in the same process pays on
# re-allocated preprocessing material.
#
# Modes are driven by SURF_TRUE, which is exported to BOTH processes of a pair:
# the flag is read before CIRCUIT_PREPROC, and do_preproc is interactive OT, so
# prover and verifier must build the same circuit set. It is set explicitly
# (to 0 or 1) rather than left unset, so a SURF_TRUE already in the caller's
# environment cannot silently turn the masked runs into TRUE runs.
#
# Usage: run_e2e.sh [-n ITERATIONS] [--modes masked|true|both]
#                   [--ip IP] [--build-dir PATH] [--timeout SEC]
set -u
iterations=10
modes_arg="both"
ip="127.0.0.1"
build_dir="$(pwd)"
timeout_s=180
while [[ $# -gt 0 ]]; do
  case "$1" in
    -n|--iterations) iterations="$2"; shift 2 ;;
    -m|--modes)      modes_arg="$2"; shift 2 ;;
    --ip)            ip="$2"; shift 2 ;;
    --build-dir)     build_dir="$2"; shift 2 ;;
    --timeout)       timeout_s="$2"; shift 2 ;;
    -h|--help)       sed -n '2,20p' "${BASH_SOURCE[0]}" >&2; exit 2 ;;
    *)               echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

case "$modes_arg" in
  both)   modes=(masked true) ;;
  masked) modes=(masked) ;;
  true)   modes=(true) ;;
  *)      echo "--modes must be 'masked', 'true' or 'both'" >&2; exit 2 ;;
esac

bin="${build_dir}/E2EBench"
if [[ ! -x "$bin" ]]; then
  echo "missing or non-executable: $bin" >&2
  echo "run this from the build directory, or pass --build-dir" >&2
  exit 1
fi

# TRUE mode needs the commit-variant Bristol circuit on disk before the first
# run; BristolFormat aborts on a missing path rather than reporting it.
if [[ " ${modes[*]} " == *" true "* ]]; then
  circuit="$(cd "${build_dir}/.." && pwd)/2pc/key-derivation/derive_gcm_verify_commit.txt"
  if [[ ! -f "$circuit" ]]; then
    echo "[runner] warning: $circuit not found; TRUE runs will abort" >&2
    echo "[runner] generate it before running with --modes true/both" >&2
  fi
fi

data_dir="$(cd "${build_dir}/.." && pwd)/data"
run_id="$(date -u +%Y%m%dT%H%M%SZ)"
log_dir="${data_dir}/${run_id}"
mkdir -p "$log_dir" || { echo "cannot create $log_dir" >&2; exit 1; }
summary="${log_dir}/summary.txt"
: > "$summary"
echo "[runner] ${iterations} iterations x {${modes[*]}}, logs in ${log_dir}"

server_pid=""; client_pid=""
cleanup() {
  [[ -n "$client_pid" ]] && kill "$client_pid" 2>/dev/null
  [[ -n "$server_pid" ]] && kill "$server_pid" 2>/dev/null
}
trap 'cleanup; exit 130' INT TERM

# run_round ROUND SERVER_LOG CLIENT_LOG SERVER_PORT VERIFIER_PORT HANDOFF_DIR SURF_TRUE
# Returns 0 on success, 1 on failure, 2 on timeout.
run_round() {
  local round="$1" server_log="$2" client_log="$3"
  local sport="$4" vport="$5" handoff="$6" surf_true="$7"

  ( cd "$build_dir" && exec env SURF_TRUE="$surf_true" "$bin" --is_server \
      --ip "$ip" -p "$sport" -v "$vport" --round "$round" \
      --handoff "$handoff" ) > "$server_log" 2>&1 &
  server_pid=$!
  sleep 0.2
  if ! kill -0 "$server_pid" 2>/dev/null; then
    server_pid=""
    return 1
  fi

  ( cd "$build_dir" && exec env SURF_TRUE="$surf_true" "$bin" \
      --ip "$ip" -p "$sport" -v "$vport" --round "$round" \
      --handoff "$handoff" ) > "$client_log" 2>&1 &
  client_pid=$!

  local timed_out=0 waited
  for (( waited = 0; waited < timeout_s; waited++ )); do
    kill -0 "$client_pid" 2>/dev/null || break
    sleep 1
  done
  if kill -0 "$client_pid" 2>/dev/null; then
    timed_out=1
    kill "$client_pid" "$server_pid" 2>/dev/null
  fi

  wait "$client_pid" 2>/dev/null; local client_rc=$?
  wait "$server_pid" 2>/dev/null; local server_rc=$?
  client_pid=""; server_pid=""

  if (( timed_out )); then
    return 2
  fi
  if (( client_rc == 0 && server_rc == 0 )); then
    return 0
  fi
  echo "    ${round}: client=${client_rc} server=${server_rc}" >&2
  return 1
}

declare -A ok_count
for mode in "${modes[@]}"; do
  ok_count["$mode"]=0
done

for iter in $(seq 1 "$iterations"); do
  itag="iter$(printf '%02d' "$iter")"

  # Mode is the inner loop so the two modes are sampled under near-identical
  # machine conditions; masked first, since a TRUE failure then cannot be
  # confused with a bad build.
  for mode_idx in "${!modes[@]}"; do
    mode="${modes[$mode_idx]}"
    [[ "$mode" == "true" ]] && surf_true=1 || surf_true=0

    ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    tag="${itag}_${mode}"
    printf '[runner] iteration %d/%d %-6s ... ' "$iter" "$iterations" "$mode"

    # Separate handoff per mode: the resumed round must replay a ticket minted
    # by a full round in the same mode.
    handoff="${log_dir}/${tag}_handoff"
    mkdir -p "$handoff"

    # Distinct ports per round and per mode so a lingering TIME_WAIT cannot
    # collide with the next listener.
    base=$((20000 + iter * 8 + mode_idx * 4))
    full_sport=$((base))
    full_vport=$((base + 1))
    res_sport=$((base + 2))
    res_vport=$((base + 3))

    run_round full \
      "${log_dir}/${tag}_full_server.log" "${log_dir}/${tag}_full_client.log" \
      "$full_sport" "$full_vport" "$handoff" "$surf_true"
    full_rc=$?

    if (( full_rc != 0 )); then
      if (( full_rc == 2 )); then
        echo "FAILED (full round timeout after ${timeout_s}s)"
        printf '%2d  %-6s  %s  full_timeout\n' "$iter" "$mode" "$ts" >> "$summary"
      else
        echo "FAILED (full round)"
        printf '%2d  %-6s  %s  full_failed\n' "$iter" "$mode" "$ts" >> "$summary"
      fi
      continue
    fi

    run_round resumed \
      "${log_dir}/${tag}_resumed_server.log" \
      "${log_dir}/${tag}_resumed_client.log" \
      "$res_sport" "$res_vport" "$handoff" "$surf_true"
    res_rc=$?

    if (( res_rc == 0 )); then
      ok_count["$mode"]=$(( ${ok_count["$mode"]} + 1 ))
      echo "ok"
      printf '%2d  %-6s  %s  ok\n' "$iter" "$mode" "$ts" >> "$summary"
    elif (( res_rc == 2 )); then
      echo "FAILED (resumed round timeout after ${timeout_s}s)"
      printf '%2d  %-6s  %s  resumed_timeout\n' "$iter" "$mode" "$ts" >> "$summary"
    else
      echo "FAILED (resumed round)"
      printf '%2d  %-6s  %s  resumed_failed\n' "$iter" "$mode" "$ts" >> "$summary"
    fi
  done
done
trap - INT TERM

echo
for mode in "${modes[@]}"; do
  echo "[runner] ${mode}: ${ok_count[$mode]}/${iterations} ok"
done
echo "[runner] logs:    ${log_dir}"
echo "[runner] summary: ${summary}"
