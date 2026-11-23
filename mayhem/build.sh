#!/usr/bin/env bash
#
# mayhem/build.sh — build Sapphire's fuzz harnesses and the functional self-test.
#
# Upstream's CMake build needs MySQL and pulls the whole server; the parsers that read untrusted
# data (packet framing, navmesh loader, datReader EXH/EXD/SqPack, base64) live in src/common and
# deps/datReader and link standalone, so this compiles exactly those sources (plus the bundled
# recastnavigation / FastLZ / zlib / spdlog submodules) directly. Everything comes from the
# checkout, so the build is offline and re-runnable. Outputs land in mayhem/build/ (gitignored by
# upstream's `build/` rule).
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
B="$SRC/mayhem/build"
R=deps/recastnavigation
mkdir -p "$B/bin"

INCS=(-Isrc/common -Ideps -Ideps/datReader -Ideps/zlib -Ideps/spdlog/include -Ideps/nlohmann/include
      -I$R/Detour/Include -I$R/DetourCrowd/Include -I$R/DetourTileCache/Include -I$R/Recast/Include
      -Ideps/FastLZ)

# Project sources reached by the harnesses (instrumented).
PROJ_SRCS=(
  src/common/Network/GamePacketParser.cpp
  src/common/Crypt/base64.cpp
  src/common/Navi/NaviProvider.cpp
  src/common/Navi/NavMeshCacheIO.cpp
  src/common/Logging/Logger.cpp
  src/common/ServiceRegistry.cpp
  src/common/Vector3.cpp
  src/common/Util/UtilMath.cpp
  deps/datReader/Exh.cpp deps/datReader/Exd.cpp deps/datReader/File.cpp
  deps/datReader/SqPack.cpp deps/datReader/Index.cpp deps/datReader/Dat.cpp
  deps/datReader/DatZlib.cpp deps/datReader/stream.cpp deps/datReader/bparse.cpp
  deps/datReader/conv.cpp deps/datReader/crc32.cpp
  $R/Detour/Source/*.cpp $R/DetourCrowd/Source/*.cpp $R/DetourTileCache/Source/*.cpp
  $R/Recast/Source/*.cpp
  deps/FastLZ/fastlz.c
)
ZLIB_SRCS=(deps/zlib/adler32.c deps/zlib/crc32.c deps/zlib/inflate.c deps/zlib/inffast.c
           deps/zlib/inftrees.c deps/zlib/zutil.c deps/zlib/deflate.c deps/zlib/trees.c
           deps/zlib/compress.c deps/zlib/uncompr.c)

# compile_all <objdir> <c/c++ flags...> : compiles PROJ_SRCS into <objdir>/libproj.a
compile_all() {
  local od="$1"; shift
  mkdir -p "$od"
  rm -f "$od"/*.o "$od"/libproj.a
  printf '%s\n' "${PROJ_SRCS[@]}" | xargs -P "$MAYHEM_JOBS" -I{} bash -c '
    s="$1"; od="$2"; shift 2
    o="$od/$(echo "$s" | tr "/" "_").o"
    extra=""
    case "$s" in *GamePacketParser.cpp) extra="${PKT_EXTRA:-}" ;; esac
    case "$s" in
      *.c) $CC "$@" -c "$s" -o "$o" ;;
      *)   $CXX -std=c++17 -include memory "$@" $extra -c "$s" -o "$o" ;;
    esac' _ {} "$od" "$@" "${INCS[@]}"
  ar rcs "$od/libproj.a" "$od"/*.o
}

# 0) Bundled zlib (dependency: uninstrumented, but with DWARF-3 debug info).
mkdir -p "$B/zlib"
rm -f "$B/zlib"/*.o "$B/libz.a"
for s in "${ZLIB_SRCS[@]}"; do $CC -O2 $DEBUG_FLAGS -Ideps/zlib -c "$s" -o "$B/zlib/$(basename "$s" .c).o"; done
ar rcs "$B/libz.a" "$B/zlib"/*.o

# 1) Project sources, sanitized + SanCov (unconditionally, so the fuzzed code reports coverage even
#    with an empty SANITIZER_FLAGS) + DWARF 3.
COV="-fsanitize=fuzzer-no-link"
# getPacket() does memcpy(data.data(), src, 0) for every zero-length segment (a 16-byte segment
# header with no payload); data.data() is NULL then, which UBSan's nonnull-attribute check aborts
# on. It is benign and would flood the packet target, so that one check is relaxed for that one
# file only; ASan and the rest of UBSan stay on and halting.
export PKT_EXTRA="-fno-sanitize=nonnull-attribute"
compile_all "$B/fuzz-obj" -O1 $SANITIZER_FLAGS $COV $DEBUG_FLAGS

$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$B/standalone_main.o"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o "$B/lsan_off.o"

# The nav_convert tool, built as-is with its main() renamed so fuzz_nav_convert can call it.
$CXX -std=c++17 -include memory -O1 $SANITIZER_FLAGS $COV $DEBUG_FLAGS "${INCS[@]}" -Dmain=nav_convert_main \
  -c src/tools/nav_convert/main.cpp -o "$B/nav_convert_main.o"

# 2) Harnesses: libFuzzer binary + standalone reproducer each.
for h in fuzz_packet fuzz_base64 fuzz_exd fuzz_sqpack fuzz_navmesh fuzz_nav_convert; do
  extra_obj=""; [ "$h" = fuzz_nav_convert ] && extra_obj="$B/nav_convert_main.o"
  $CXX -std=c++17 -O1 $SANITIZER_FLAGS $COV $DEBUG_FLAGS "${INCS[@]}" -c "mayhem/harnesses/$h.cpp" -o "$B/$h.o"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$B/$h.o" $extra_obj "$B/lsan_off.o" \
    "$B/fuzz-obj/libproj.a" "$B/libz.a" -lpthread -lm -o "$B/bin/$h"
  $CXX $SANITIZER_FLAGS $COV $DEBUG_FLAGS "$B/standalone_main.o" "$B/$h.o" $extra_obj "$B/lsan_off.o" \
    "$B/fuzz-obj/libproj.a" "$B/libz.a" -lpthread -lm -o "$B/bin/$h-standalone"
done

# 3) Functional self-test (known-answer checks on the same parsers), NORMAL flags.
compile_all "$B/test-obj" -O1 $COVERAGE_FLAGS
$CXX -std=c++17 -include memory -O1 $COVERAGE_FLAGS "${INCS[@]}" mayhem/selftest/selftest.cpp \
  "$B/test-obj/libproj.a" "$B/libz.a" -lpthread -lm -o "$B/bin/sapphire_selftest"

echo "built: $(ls "$B/bin" | tr '\n' ' ')"
