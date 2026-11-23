#!/usr/bin/env bash
#
# mayhem/test.sh — RUN the known-answer self-test built by mayhem/build.sh
# (mayhem/selftest/selftest.cpp, normal flags). Upstream ships no unit tests, so the self-test
# asserts concrete decoded values from the same parsers the fuzz targets reach: base64 known
# answers, packet framing results/segment payloads, EXH/EXD decoded row values, and navmesh
# load / cache round-trip / bad-magic rejection.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SRC:=/mayhem}"
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

EXPECTED=14
bin="$SRC/mayhem/build/bin/sapphire_selftest"
if [ ! -x "$bin" ]; then
  echo "missing $bin — run mayhem/build.sh first" >&2
  emit_ctrf "sapphire-selftest" 0 "$EXPECTED"
  exit 1
fi
out="$("$bin" 2>&1)"; rc=$?
echo "$out"
passed=$(grep -c '^PASS ' <<<"$out" || true)
failed=$(grep -c '^FAIL ' <<<"$out" || true)
# Checks that never reported (crash, early exit, no-op binary) count as failures.
missing=$(( EXPECTED - passed - failed ))
[ "$missing" -gt 0 ] && failed=$(( failed + missing ))
[ "$rc" -ne 0 ] && [ "$failed" -eq 0 ] && failed=1
emit_ctrf "sapphire-selftest" "$passed" "$failed"
