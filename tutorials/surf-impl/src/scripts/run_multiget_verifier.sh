#!/usr/bin/env bash
# Verifier half of a split-host MultiGetBench run. Runs on the machine that
# plays V; the prover half (run_multiget_prover.sh) runs on the machine that
# plays C, with the origin either local to C or reached with --host.
#
# The two scripts do not talk to each other. They stay in step because they
# derive the SAME port schedule from the SAME options, and because each side
# runs one process per round and waits for it to exit before starting the next.
# A verifier that is up before its prover simply blocks in accept() until
# --timeout expires, so starting this side FIRST is the safe order.
#
# Both sides must be given identical -n, --modes, --resumed and --port-base.
#
# This side writes the *_server.log files that aggregate_e2e.py parses: the
# per-phase TIMINGS / DATA / rounds blocks come from Server::run(), which only
# the verifier walks.
#
# Handoff: this side reads and writes only the verifier's PSK share, so its
# handoff directory is local to this host and must NOT be shared with C.
#
# Usage: run_multiget_verifier.sh --ip <bind-ip> [-n ITERATIONS]
#                                 [--modes masked|true|both] [--resumed N]
#                                 [--port-base N] [--build-dir PATH]
#                                 [--timeout SEC]
set -u

iterations=1
modes_arg="both"
ip=""
build_dir="$(pwd)"
timeout_s=600
resumed_rounds=2
port_base=20000

while [[ $# -gt 0 ]]; do
  case "$1" in
    -n|--iterations) iterations="$2"; shift 2 ;;
    -m|--modes)      modes_arg="$2"; shift 2 ;;
    --ip)            ip="$2"; shift 2 ;;
    --resumed)       resumed_rounds="$2"; shift 2 ;;
    --port-base)     port_base="$2"; shift 2 ;;
    --build-dir)     build_dir="$2"; shift 2 ;;
    --timeout)       timeout_s="$2"; shift 2 ;;
    -h|--help)       sed -n '2,28p' "${BASH_SOURCE[0]}" >&2; exit 2 ;;
    *)               echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "$ip" ]]; then
  echo "--ip is required: it is the address this verifier binds, and the" >&2
  echo "address the prover must be given as --verifier-ip" >&2
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

# TRUE mode needs the commit-variant Bristol circuit on disk; BristolFormat
# aborts on a missing path rather than reporting it.
if [[ " ${modes[*]} " == *" true "* ]]; then
  circuit="$(cd "${build_dir}/.." && pwd)/2pc/key-derivation/derive_gcm_verify_commit.txt"
  [[ -f "$circuit" ]] || echo "[verifier] warning: $circuit not found; TRUE runs will abort" >&2
fi

data_dir="$(cd "${build_dir}/.." && pwd)/data"
run_id="$(date -u +%Y%m%dT%H%M%SZ)"
log_dir="${data_dir}/${run_id}"
mkdir -p "$log_dir" || { echo "cannot create $log_dir" >&2; exit 1; }
summary="${log_dir}/summary.txt"
: > "$summary"

echo "[verifier] binding ${ip}, ports from ${port_base}"
echo "[verifier] ${iterations} iteration(s) x {${modes[*]}}, ${resumed_rounds} resumed round(s) each"
echo "[verifier] logs in ${log_dir}"
echo "[verifier] start the prover with:"
echo "           run_multiget_prover.sh --verifier-ip ${ip} -n ${iterations} \\"
echo "               --modes ${modes_arg} --resumed ${resumed_rounds} --port-base ${port_base}"
echo

verifier_pid=""
cleanup() { [[ -n "$verifier_pid" ]] && kill "$verifier_pid" 2>/dev/null; }
trap 'cleanup; exit 130' INT TERM

# One verifier process, one round. Returns its exit code.
run_verifier() {
  local round="$1" vport="$2" handoff="$3" surf_true="$4" server_log="$5"

  ( cd "$build_dir" && exec env SURF_TRUE="$surf_true" "$bin" --is_verifier \
      --verifier_ip "$ip" -v "$vport" --round "$round" --handoff "$handoff" \
      --accept_timeout_ms $(( timeout_s * 1000 )) ) > "$server_log" 2>&1 &
  verifier_pid=$!

  wait "$verifier_pid" 2>/dev/null
  local rc=$?
  verifier_pid=""
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
    echo "[verifier] iteration ${iter}/${iterations} ${mode}"

    # Local to this host: only the verifier's own PSK share lives here.
    handoff="${log_dir}/${tag}_handoff"
    mkdir -p "$handoff"

    # MUST match the prover's formula exactly.
    base=$(( port_base + (iter * 2 + mode_idx) * (resumed_rounds + 2) ))
    vport_full=$(( base + 1 ))

    printf '  full (port %d) ... ' "$vport_full"
    run_verifier full "$vport_full" "$handoff" "$surf_true" \
      "${log_dir}/${tag}_full_server.log"
    rc=$?
    if (( rc != 0 )); then
      echo "FAILED (rc=$rc)"
      printf '%2d  %-6s  %s  full_failed\n' "$iter" "$mode" "$ts" >> "$summary"
      continue
    fi
    echo "ok"

    resumed_ok=0; resumed_fail=0
    for (( k = 1; k <= resumed_rounds; k++ )); do
      rtag="${itag}r$(printf '%02d' "$k")_${mode}"
      vport=$(( vport_full + k ))
      printf '  resumed %d/%d (port %d) ... ' "$k" "$resumed_rounds" "$vport"
      run_verifier resumed "$vport" "$handoff" "$surf_true" \
        "${log_dir}/${rtag}_resumed_server.log"
      rc=$?
      if (( rc == 0 )); then
        echo "ok"; resumed_ok=$(( resumed_ok + 1 ))
      else
        echo "FAILED (rc=$rc)"; resumed_fail=$(( resumed_fail + 1 )); break
      fi
    done

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
  echo "[verifier] ${mode}: ${ok_count[$mode]}/${iterations} iteration(s) fully ok"
done
echo "[verifier] logs:    ${log_dir}"
echo "[verifier] summary: ${summary}"
echo "[verifier] aggregate: ./aggregate_e2e.py ${log_dir}"
