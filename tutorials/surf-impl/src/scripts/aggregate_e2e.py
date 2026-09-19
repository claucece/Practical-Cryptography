#!/usr/bin/env python3
"""Aggregate E2EBench verifier metrics across iterations.

Usage:
    ./aggregate_e2e.py ../data/20260813T081731Z
    ./aggregate_e2e.py ../data/20260813T081731Z --metric time_ms --warmup 1
    ./aggregate_e2e.py ../data/20260813T081731Z --mode true
"""

import argparse
import re
import statistics
import sys
from pathlib import Path

OFFLINE = [
    ("Circuit preprocessing",       [("CIRCUIT_PREPROC", +1)]),
    ("Commit to 2PC-AES masks",     [("MASK_COMMIT", +1)]),
    ("Connect to V",                [("HANDSHAKE", +1), ("HANDSHAKE_DONE", +1)]),
    ("Joint key share",             [("READING_KS", +1), ("MAKING_KS", +1),
                                     ("WRITING_KS", +1)]),
]

HANDSHAKE = [
    ("Binder",                      [("PSK_BINDER", +1)]),
    ("Server key share",            [("READING_SKS", +1)]),
    ("ECtF",                        [("ECTF_WAIT", +1), ("ECTF_DONE", +1)]),
    ("Handshake keys",              [("KS_CIRCUIT", +1), ("KS_DONE", +1)]),
    ("Reveal full HS keys",         [("CERT_WRITE", +1)]),
    ("Traffic secrets",             [("DERIVE_TS", +1)]),
    ("GHASH shares",                [("DERIVE_GCM_SHARES", +1)]),
    ("Resumption secret",           [("DERIVE_RES", +1)]),
]

RECORD_LAYER = [
    ("Await ticket",                [("DERIVE_PSK_WAIT", +1), ("AES_ENCRYPT", -1),
                                     ("GCM_TAG", -1), ("KS_DERIVE", -1),
                                     ("GCM_VERIFY", -1)]),
    ("PSK secret",                  [("DERIVE_PSK", +1)]),
    ("Encrypt in 2PC",              [("AES_ENCRYPT", +1)]),
    ("Create tags for encryption",  [("GCM_TAG", +1)]),
    ("Verify tags for decryption",  [("GCM_VERIFY", +1)]),
    ("Derive keystream in 2PC",     [("KS_DERIVE", +1)]),
    ("Commit to key share",         [("KEY_COMMIT", +1)]),
    ("Release k_v",                 [("KEY_RELEASE", +1)]),
]

WAITS = [
    ("Await cert commitment",       [("CERT_WAIT", +1)]),
    ("Await prover (HS keys)",      [("KS_WAIT", +1), ("KS_CIRCUIT", -1)]),
    ("Await traffic-secret start",  [("DERIVE_TS_WAIT", +1), ("DERIVE_TS", -1)]),
]

SECTIONS = [
    ("Offline", OFFLINE),
    ("Online -- handshake", HANDSHAKE),
    ("Online -- record layer", RECORD_LAYER),
    ("Waits (verifier idle)", WAITS),
]

# ACCEPT is the verifier idling before a prover connects, which is a property of
# the harness, not the protocol. SESSION_TICKET has a TIME scope but no
# bandwidth tracking.
IGNORED = {"ACCEPT", "SESSION_TICKET"}

METRICS = [
    ("time_ms", "ms",  "{:10.2f} ms"),
    ("bw_mib",  "MiB", "{:10.4f} MiB"),
    ("rounds",  "rounds", "{:10.1f}"),
]

MODES = ("masked", "true")

TIME_RE   = re.compile(r"^([A-Z_0-9]+):([-+0-9.eE]+)s$")
BW_RE     = re.compile(r"^([A-Z_0-9]+):([-+0-9.eE]+) MiB$")
ROUNDS_RE = re.compile(r"^([A-Z_0-9]+):([0-9]+) rounds$")

MODE_RE = re.compile(r"_(" + "|".join(MODES) + r")_(?:full|resumed)_server\.log$")

# run_multiget.sh names each resumed round iterNNrKK_<mode>_resumed_server.log.
# KK says which asset in the queue that round fetched, so rounds with different
# KK measure different responses and must never be pooled: averaging a 4 KB
# stylesheet with a 1.9 MB image gives a figure that describes neither, and the
# record-layer phases scale with record count. Each KK is reported separately.
# Logs with no rKK segment (run_e2e.sh, legacy) form a single unnumbered group.
ROUND_RE = re.compile(r"\dr(\d+)_(?:" + "|".join(MODES) + r")_resumed_server\.log$")


def mode_from_name(path):
    """The mode run_e2e.sh baked into the filename, or None for older logs."""
    m = MODE_RE.search(path.name)
    return m.group(1) if m else None


def round_group(path):
    """Which resumed round of the iteration this log is, or None if untagged."""
    m = ROUND_RE.search(path.name)
    return int(m.group(1)) if m else None


def asset_for(path):
    """Best-effort: the path this round fetched, from the sibling prover log.

    The verifier never sees the URL, so the label comes from the prover's
    SUMMARY line. Absent (or a differently-named harness) just means the group
    is reported by round number alone.
    """
    prover = path.with_name(path.name.replace("_server.log", "_prover.log"))
    if not prover.is_file():
        return None
    try:
        text = prover.read_text(errors="replace")
    except OSError:
        return None
    for line in text.splitlines():
        if "SUMMARY" not in line:
            continue
        m = re.search(r"\bpath=(\S+)", line)
        if m:
            return m.group(1)
    return None


def detect_mode(events_by_iter):
    """Fallback for logs with no mode in the filename. TRUE mode never runs the
    keystream circuit, so KS_DERIVE is absent or zero in every round; masked
    mode always has it."""
    for e in events_by_iter:
        if e.get("KS_DERIVE", 0) > 0:
            return "masked"
    return "true"


def numeric_key(path):
    """Sort iter02 before iter10 rather than lexicographically."""
    nums = re.findall(r"\d+", path.name)
    return ([int(n) for n in nums], path.name)


def parse_log(path):
    """Return a list of per-round metric dicts, one per TIMINGS block."""
    rounds = []
    current = None
    for line in path.read_text(errors="replace").splitlines():
        if line.startswith("TIMINGS"):
            if current:
                rounds.append(current)
            current = {"time_ms": {}, "bw_mib": {}, "rounds": {}}
            continue
        if current is None:
            continue
        s = line.strip()
        m = TIME_RE.match(s)
        if m:
            current["time_ms"][m.group(1)] = float(m.group(2)) * 1000.0
            continue
        m = BW_RE.match(s)
        if m:
            current["bw_mib"][m.group(1)] = float(m.group(2))
            continue
        m = ROUNDS_RE.match(s)
        if m:
            current["rounds"][m.group(1)] = float(m.group(2))
    if current:
        rounds.append(current)

    deduped = []
    for r in rounds:
        if deduped and r == deduped[-1]:
            continue
        deduped.append(r)
    return deduped


def phase_value(events, spec, metric):
    """Sum a phase's constituent events.
    """
    total, seen = 0.0, False
    for name, sign in spec:
        if sign < 0 and metric != "time_ms":
            continue
        if name in events:
            total += sign * events[name]
            seen = True
    return total if seen else None


def fmt(value, spec):
    if value is None:
        return "--".rjust(len(spec.format(0)))
    return spec.format(value)


def report(label, per_iter_rounds, metric, unit, spec, mode=None):
    n = len(per_iter_rounds)
    if n == 0:
        return
    events_by_iter = [r[metric] for r in per_iter_rounds]
    if not any(events_by_iter):
        return

    if mode is None:
        mode = detect_mode(events_by_iter)

    width = 34 + 4 * len(spec.format(0))
    print()
    print("=" * width)
    print(f"{label} [{mode} mode] -- {unit}   "
          f"({n} iteration{'s' if n != 1 else ''})")
    print("=" * width)

    pad = len(spec.format(0))
    for section, phases in SECTIONS:
        rows = []
        for name, spec_events in phases:
            vals = [v for v in (phase_value(e, spec_events, metric)
                                for e in events_by_iter) if v is not None]
            if not vals or all(v == 0 for v in vals):
                continue
            rows.append((name, vals))
        if not rows:
            continue

        print(f"\n{section}")
        print(f"  {'phase':<30} {'mean':>{pad}} {'median':>{pad}} "
              f"{'min':>{pad}} {'max':>{pad}}")
        print(f"  {'-' * 30} {'-' * pad} {'-' * pad} {'-' * pad} {'-' * pad}")

        section_means = []
        for name, vals in rows:
            section_means.append(statistics.mean(vals))
            print(f"  {name:<30} {fmt(statistics.mean(vals), spec)} "
                  f"{fmt(statistics.median(vals), spec)} "
                  f"{fmt(min(vals), spec)} {fmt(max(vals), spec)}")

        print(f"  {'-' * 30}")
        print(f"  {'subtotal (mean)':<30} {fmt(sum(section_means), spec)}")

    online_mean = 0.0
    for section, phases in SECTIONS:
        if section == "Offline" or section.startswith("Waits"):
            continue
        for _, spec_events in phases:
            vals = [v for v in (phase_value(e, spec_events, metric)
                                for e in events_by_iter) if v is not None]
            if vals:
                online_mean += statistics.mean(vals)
    print(f"\n  {'ONLINE TOTAL (mean)':<30} {fmt(online_mean, spec)}")

    seen = {k for e in events_by_iter for k in e}
    mapped = {name for _, phases in SECTIONS for _, sp in phases
              for name, _ in sp}
    unmapped = seen - mapped - IGNORED
    if unmapped:
        print(f"\n  UNMAPPED: {', '.join(sorted(unmapped))}")


def raw_dump(label, per_iter_rounds, names):
    print(f"\n--- {label}: per-iteration time_ms, in iteration order")
    for name, rnd in zip(names, per_iter_rounds):
        parts = []
        for _, phases in SECTIONS:
            for phase, spec_events in phases:
                v = phase_value(rnd["time_ms"], spec_events, "time_ms")
                if v is not None and v >= 0.05:
                    parts.append(f"{phase}={v:.2f}")
        print(f"  {name}: " + "  ".join(parts))


def discover_modes(log_dir):
    """Which mode groups are present. None means unlabelled (pre-sweep) logs."""
    found, unlabelled = set(), False
    for path in log_dir.glob("*_server.log"):
        if not (path.name.endswith("_full_server.log")
                or path.name.endswith("_resumed_server.log")):
            continue
        m = mode_from_name(path)
        if m:
            found.add(m)
        else:
            unlabelled = True
    modes = [m for m in MODES if m in found]
    if unlabelled:
        modes.append(None)
    return modes


def collect(log_dir, warmup, mode=None):
    """Return (full, resumed_groups, full_names, notes) for one mode.

    |resumed_groups| maps a round number (or None when untagged) to
    (rounds, names, asset): one entry per distinct resumed round, each holding
    one sample per iteration. Grouping rather than pooling keeps rounds that
    fetched different assets out of each other's statistics.

    |mode| filters on the filename tag; None selects logs with no tag, which is
    also the legacy single-process layout.
    """
    notes = []
    full, resumed_groups = [], {}
    full_names = []

    def add_group(key, paths, asset_hint=True):
        rounds, names, asset = [], [], None
        for path in paths:
            blocks = parse_log(path)
            if not blocks:
                notes.append((path.name, "no timings"))
                continue
            if len(blocks) > 1:
                notes.append((path.name,
                              f"{len(blocks)} blocks, using the first"))
            rounds.append(blocks[0])
            names.append(path.name)
            if asset_hint and asset is None:
                asset = asset_for(path)
        if rounds:
            resumed_groups[key] = (rounds, names, asset)

    def wanted(paths):
        return [p for p in paths if mode_from_name(p) == mode]

    split_full = wanted(sorted(log_dir.glob("*_full_server.log"),
                               key=numeric_key))
    split_resumed = wanted(sorted(log_dir.glob("*_resumed_server.log"),
                                  key=numeric_key))

    if split_full or split_resumed:
        for path in split_full[warmup:]:
            blocks = parse_log(path)
            if not blocks:
                notes.append((path.name, "no timings"))
                continue
            if len(blocks) > 1:
                notes.append((path.name,
                              f"{len(blocks)} blocks, using the first"))
            full.append(blocks[0])
            full_names.append(path.name)

        # split_resumed is already in (iteration, round) order, so bucketing by
        # round number leaves each bucket in iteration order. --warmup then
        # drops leading iterations from each bucket independently.
        by_round = {}
        for path in split_resumed:
            by_round.setdefault(round_group(path), []).append(path)
        for key in sorted(by_round, key=lambda k: (k is None, k)):
            add_group(key, by_round[key][warmup:])
        return full, resumed_groups, full_names, notes

    if mode is not None:
        return full, resumed_groups, full_names, notes

    legacy = sorted(log_dir.glob("*_server.log"), key=numeric_key)[warmup:]
    if legacy:
        notes.append(("(layout)", "single-process logs; resumed round is an "
                                  "upper bound, see RoundHandoff.hpp"))
    legacy_resumed, legacy_names = [], []
    for path in legacy:
        blocks = parse_log(path)
        if not blocks:
            notes.append((path.name, "no timings"))
            continue
        full.append(blocks[0])
        full_names.append(path.name)
        if len(blocks) >= 2:
            legacy_resumed.append(blocks[1])
            legacy_names.append(path.name)
        else:
            notes.append((path.name, "no resumed round"))
        if len(blocks) > 2:
            notes.append((path.name,
                          f"{len(blocks)} blocks, using first two"))
    if legacy_resumed:
        resumed_groups[None] = (legacy_resumed, legacy_names, None)
    return full, resumed_groups, full_names, notes


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("log_dir", nargs="?", help="run directory under ../data")
    ap.add_argument("--metric", choices=[m for m, _, _ in METRICS],
                    help="report only this metric")
    ap.add_argument("--mode", choices=list(MODES),
                    help="report only this SURF mode")
    ap.add_argument("--warmup", type=int, default=0,
                    help="discard this many leading iterations")
    ap.add_argument("--raw", action="store_true",
                    help="also print per-iteration values in iteration order")
    args = ap.parse_args()

    if args.log_dir:
        log_dir = Path(args.log_dir)
    else:
        data = Path("../data")
        if not data.is_dir():
            sys.exit("no ../data directory; pass a log dir explicitly")
        runs = sorted(p for p in data.iterdir() if p.is_dir())
        if not runs:
            sys.exit(f"no run directories under {data}")
        log_dir = runs[-1]

    if not log_dir.is_dir():
        sys.exit(f"not a directory: {log_dir}")

    modes = discover_modes(log_dir)
    if args.mode:
        if args.mode not in modes:
            sys.exit(f"no {args.mode}-mode logs in {log_dir}")
        modes = [args.mode]
    if not modes:
        sys.exit(f"no parseable server logs in {log_dir}")

    def group_label(key, asset):
        label = "PSK RESUMPTION"
        if key is not None:
            label += f" round {key}"
        if asset:
            label += f" -- {asset}"
        return label

    reported = False
    for mode in modes:
        full, resumed_groups, full_names, notes = collect(
            log_dir, args.warmup, mode)
        if not full and not resumed_groups:
            continue
        reported = True

        tag = mode if mode else "unlabelled"
        n_resumed = sum(len(r) for r, _, _ in resumed_groups.values())
        print()
        print(f"### {tag} mode: {len(full)} full and {n_resumed} resumed "
              f"rounds from {log_dir}")
        if len(resumed_groups) > 1:
            print(f"    resumed rounds are reported as "
                  f"{len(resumed_groups)} separate groups, one per asset; "
                  f"they are never pooled")
        if args.warmup:
            print(f"(discarded the first {args.warmup} iteration(s))")

        if notes:
            print("\nnotes:")
            for name, why in notes:
                print(f"  {name}: {why}")

        if args.raw:
            raw_dump("FULL HANDSHAKE", full, full_names)
            for key, (rounds, names, asset) in resumed_groups.items():
                raw_dump(group_label(key, asset), rounds, names)

        for metric, unit, spec in METRICS:
            if args.metric and metric != args.metric:
                continue
            report("FULL HANDSHAKE", full, metric, unit, spec, mode)
            for key, (rounds, _, asset) in resumed_groups.items():
                report(group_label(key, asset), rounds, metric, unit, spec,
                       mode)

    if not reported:
        sys.exit(f"no parseable server logs in {log_dir}")


if __name__ == "__main__":
    main()
