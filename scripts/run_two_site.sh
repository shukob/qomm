#!/usr/bin/env bash
# Genuinely geographic 7-party run: some parties local, the rest on a remote host.
#
# The proposal lists "geographically distributed 7 nodes" as unverified, because
# the existing fixture emulates delay with loopback proxies on one machine. Here
# the inter-party links carry real propagation delay between two sites. The
# remote host only exposes SSH, so every cross-site link is carried inside one
# SSH connection; the encryption is doubled but the round trips are real.
set -uo pipefail

LOCAL_ROOT="${LOCAL_MP_SPDZ_ROOT:?set LOCAL_MP_SPDZ_ROOT}"
# No defaults: an ssh alias and a path on someone's machine are that person's
# infrastructure, and the same reasoning that labels hosts in the artifacts says
# they do not belong in a script either.
REMOTE_HOST="${REMOTE_HOST:?set REMOTE_HOST to the second site}"
REMOTE_ROOT="${REMOTE_MP_SPDZ_ROOT:?set REMOTE_MP_SPDZ_ROOT to its MP-SPDZ checkout}"
QOMM_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
N_MM="${N_MM:-16}"
MODE="${MODE:-rfq}"
N_PARTIES=7
LOCAL_PARTIES="${LOCAL_PARTIES:-0 1 2}"
REMOTE_PARTIES="${REMOTE_PARTIES:-3 4 5 6}"
BASE_PORT="${BASE_PORT:-24100}"
REPEATS="${REPEATS:-3}"
REMOTE_ADDR="${REMOTE_ADDR:-221.109.63.105}"
REMOTE_PORT="${REMOTE_PORT:-22}"
PROGRAM="qomm_twosite_${MODE}_m${N_MM}"
OUT="${OUT:-$QOMM_DIR/artifacts/two_site_${MODE}_m${N_MM}.json}"

WORK="$(mktemp -d)"
trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$WORK"' EXIT

echo "== generating program and inputs =="
python3 "$QOMM_DIR/mp_spdz/gen_qomm.py" --n-mm "$N_MM" --mode "$MODE" \
  --n-parties "$N_PARTIES" --out-program "$WORK/$PROGRAM.mpc" \
  --out-input-dir "$WORK/inputs" --out-reference "$WORK/reference.json"

cp "$WORK/$PROGRAM.mpc" "$LOCAL_ROOT/Programs/Source/$PROGRAM.mpc"
for p in $(seq 0 6); do cp "$WORK/inputs/Input-P$p-0" "$LOCAL_ROOT/Player-Data/"; done

echo "== compiling once, locally =="
( cd "$LOCAL_ROOT" && python3 ./compile.py -F 128 "$PROGRAM" >"$WORK/compile.log" 2>&1 ) || {
  tail -20 "$WORK/compile.log"; exit 2; }
grep -E "virtual machine rounds|integer triples" "$WORK/compile.log" || true

echo "== shipping bytecode, inputs and certificates into a private remote tree =="
# A shared MP-SPDZ checkout has exactly one Player-Data directory. Writing into
# it would corrupt any measurement already running there, so this fixture gets
# its own tree with the party binary symlinked in.
REMOTE_RUN="$REMOTE_ROOT/../two_site_run_$$"
ssh "$REMOTE_HOST" "mkdir -p '$REMOTE_RUN/Programs/Bytecode' '$REMOTE_RUN/Programs/Schedules' '$REMOTE_RUN/Player-Data' && ln -sf '$REMOTE_ROOT/malicious-shamir-party.x' '$REMOTE_RUN/'"
scp -q "$LOCAL_ROOT/Programs/Schedules/$PROGRAM.sch" "$REMOTE_HOST:$REMOTE_RUN/Programs/Schedules/"
scp -q "$LOCAL_ROOT"/Programs/Bytecode/"$PROGRAM"-*.bc "$REMOTE_HOST:$REMOTE_RUN/Programs/Bytecode/"
scp -q "$WORK"/inputs/Input-P*-0 "$REMOTE_HOST:$REMOTE_RUN/Player-Data/"
scp -q "$LOCAL_ROOT"/Player-Data/*.pem "$LOCAL_ROOT"/Player-Data/*.key "$REMOTE_HOST:$REMOTE_RUN/Player-Data/" 2>/dev/null || true
ssh "$REMOTE_HOST" "cd '$REMOTE_RUN/Player-Data' && c_rehash . >/dev/null 2>&1 || true"

echo "== opening cross-site tunnels =="
FWD=()
for p in $REMOTE_PARTIES; do FWD+=(-L "127.0.0.1:$((BASE_PORT+p)):127.0.0.1:$((BASE_PORT+p))"); done
for p in $LOCAL_PARTIES;  do FWD+=(-R "127.0.0.1:$((BASE_PORT+p)):127.0.0.1:$((BASE_PORT+p))"); done
ssh -N -o ExitOnForwardFailure=yes -o ServerAliveInterval=15 "${FWD[@]}" "$REMOTE_HOST" &
TUNNEL=$!
sleep 4
kill -0 "$TUNNEL" 2>/dev/null || { echo "tunnel failed"; exit 3; }

# every party reaches every other party through its own loopback
: > "$WORK/hosts"
for p in $(seq 0 6); do echo "127.0.0.1:$((BASE_PORT+p))" >> "$WORK/hosts"; done
cp "$WORK/hosts" "$LOCAL_ROOT/qomm_hosts_$$"
scp -q "$WORK/hosts" "$REMOTE_HOST:$REMOTE_RUN/qomm_hosts"

echo "== measuring real round-trip delay on the tunnelled path =="
RTT=$(python3 "$QOMM_DIR/scripts/tcp_rtt.py" "$REMOTE_ADDR" "$REMOTE_PORT")
echo "measured TCP round trip to the remote site: ${RTT} ms"

samples=()
for run in $(seq 1 "$REPEATS"); do
  echo "== run $run =="
  start=$(python3 -c 'import time;print(time.time_ns())')
  for p in $LOCAL_PARTIES; do
    ( cd "$LOCAL_ROOT" && ./malicious-shamir-party.x "$p" "$PROGRAM" -N 7 -T 2 -ip "qomm_hosts_$$" ) \
      > "$WORK/party-$p.log" 2>&1 &
  done
  sleep 2
  for p in $REMOTE_PARTIES; do
    ssh "$REMOTE_HOST" "cd '$REMOTE_RUN' && ./malicious-shamir-party.x $p $PROGRAM -N 7 -T 2 -ip qomm_hosts" \
      > "$WORK/party-$p.log" 2>&1 &
  done
  status=0
  for job in $(jobs -p); do [[ "$job" == "$TUNNEL" ]] && continue; wait "$job" || status=1; done
  end=$(python3 -c 'import time;print(time.time_ns())')
  elapsed=$(python3 -c "print(($end-$start)/1e9)")
  echo "  elapsed ${elapsed}s status=$status"
  samples+=("$elapsed")
  grep -h "QOMM_BEST" "$WORK"/party-*.log | head -2 || true
done

python3 - "$OUT" "$WORK" "$RTT" "$N_MM" "$MODE" "${samples[@]}" <<'PY'
import json, pathlib, re, statistics, socket, sys
out, work, rtt, n_mm, mode, *samples = sys.argv[1:]
work = pathlib.Path(work)
logs = "\n".join(p.read_text(errors="replace") for p in sorted(work.glob("party-*.log")))
compile_log = (work / "compile.log").read_text(errors="replace")
def grab(pattern, text, cast=float):
    m = re.search(pattern, text, re.M)
    return cast(m.group(1).replace(",", "")) if m else None
reference = json.loads((work / "reference.json").read_text())
got_price = grab(r"QOMM_BEST_PRICE=(-?\d+)", logs, int)
got_mm = grab(r"QOMM_BEST_MM=(\d+)", logs, int)
values = [float(s) for s in samples]
payload = {
  "fixture": "two-site geographic run over SSH-tunnelled links",
  "mode": mode, "n_mm": int(n_mm), "parties": 7, "threshold": 2,
  "local_host": socket.gethostname(),
  "measured_tcp_round_trip_ms": float(rtt),
  "wall_seconds": values,
  "wall_median": statistics.median(values) if values else None,
  "vm_rounds": grab(r"([\d,]+)\s+virtual machine rounds", compile_log, int),
  "integer_triples": grab(r"([\d,]+)\s+integer triples", compile_log, int),
  "party_time_seconds": grab(r"^Time\s*=\s*([\d.]+)", logs),
  "startup_stagger_seconds": 2.0,
  "party_mb": grab(r"Data sent\s*=\s*([\d.]+)\s*MB", logs),
  "party_rounds": grab(r"Data sent.*in ~([\d,]+) rounds", logs, int),
  "verified": got_price == reference["best_price"] and got_mm == reference["best_mm"],
  "expected": {"best_price": reference["best_price"], "best_mm": reference["best_mm"]},
  "observed": {"best_price": got_price, "best_mm": got_mm},
  "claim_boundary": "real inter-site propagation delay; transport is TCP inside SSH, "
                    "not a direct MP-SPDZ TLS socket, and only two sites are used",
}
pathlib.Path(out).parent.mkdir(parents=True, exist_ok=True)
pathlib.Path(out).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
print(json.dumps(payload, indent=2, sort_keys=True))
PY

rm -f "$LOCAL_ROOT/qomm_hosts_$$" "$LOCAL_ROOT/Programs/Source/$PROGRAM.mpc"
ssh "$REMOTE_HOST" "rm -rf '$REMOTE_RUN'" || true
