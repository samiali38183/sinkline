#!/usr/bin/env bash
# Reproduce the external benchmark. Usage: bench/external/run.sh <workdir> <result-label> [tools...]
# Needs: git, python3.9+, and (for the comparison tools) `pip install bandit==1.9.4 semgrep==1.185.0`.
# Nothing from the benchmark is copied into this repository; it is cloned into <workdir>.
set -euo pipefail

WORK="${1:?workdir}"; LABEL="${2:?label, e.g. v0.5.0}"; shift 2
PIN=f1291485808b66e20ddb6b01b10dc71b3df8c8ba      # OWASP-Benchmark/BenchmarkPython, 2026-05-19
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "$WORK"
if [ ! -d "$WORK/BenchmarkPython" ]; then
  git clone -q https://github.com/OWASP-Benchmark/BenchmarkPython "$WORK/BenchmarkPython"
fi
git -C "$WORK/BenchmarkPython" checkout -q "$PIN"
cd "$WORK/BenchmarkPython"
mkdir -p "$WORK/raw"

TOOLS=("$@"); [ ${#TOOLS[@]} -eq 0 ] && TOOLS=(sinkline)
ARGS=()
for t in "${TOOLS[@]}"; do
  case "$t" in
    sinkline) sinkline scan . --format json -o "$WORK/raw/sinkline-$LABEL.json" || true
              ARGS+=("sinkline=$WORK/raw/sinkline-$LABEL.json") ;;
    bandit)   bandit -r . -f json -o "$WORK/raw/bandit.json" -q || true
              ARGS+=("bandit=$WORK/raw/bandit.json") ;;
    semgrep)  semgrep scan --config p/python --config p/owasp-top-ten --json --metrics=off --quiet \
                -o "$WORK/raw/semgrep.json" .
              ARGS+=("semgrep=$WORK/raw/semgrep.json") ;;
  esac
done
python "$HERE/score.py" --expected expectedresults-0.1.csv --out-dir "$HERE/results/$LABEL" "${ARGS[@]}"
