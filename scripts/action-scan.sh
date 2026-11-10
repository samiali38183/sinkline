#!/usr/bin/env bash
# Run by action.yml. Inputs arrive as environment variables (INPUT_PATH, INPUT_FAIL_ON,
# INPUT_MIN_CONFIDENCE), never interpolated into this script's text, and are only ever used
# quoted, as single argv entries. See "Using the GitHub Action safely" in the README.
set -u

fail_on="${INPUT_FAIL_ON:-}"
min_conf="${INPUT_MIN_CONFIDENCE:-low}"
path="${INPUT_PATH:-.}"

case "$fail_on" in
  ""|low|medium|high|critical) ;;
  *) echo "::error::fail-on must be empty, low, medium, high or critical"; exit 2 ;;
esac
case "$min_conf" in
  low|medium|high) ;;
  *) echo "::error::min-confidence must be low, medium or high"; exit 2 ;;
esac
# a path that starts with "-" would be parsed as an option
case "$path" in
  -*) path="./$path" ;;
esac

args=(scan "$path" --format sarif -o sinkline.sarif --min-confidence "$min_conf")
if [ -n "$fail_on" ]; then
  args+=(--fail-on "$fail_on")
fi

rc=0
sinkline "${args[@]}" || rc=$?
if [ "$rc" -ne 0 ]; then
  # keep going so the SARIF upload step still runs; the last step fails the job
  echo "SINKLINE_RC=$rc" >> "${GITHUB_ENV:-/dev/null}"
fi
exit 0
