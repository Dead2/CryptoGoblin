rm -rf CMakeFiles/ CMakeCache.txt

# CFLAGS
general="-O2 -pipe -Wall -Wextra -fdiagnostics-color=always -fuse-linker-plugin"
protect=""   # -fstack-protector
codegen="--fast-math -fomit-frame-pointer -momit-leaf-frame-pointer -fvisibility-inlines-hidden -fvisibility=internal -mlong-double-64 -fno-signed-zeros"
params=" --param max-cse-path-length=20 --param max-cse-insns=2000 --param max-cselib-memory-locations=1000 --param max-reload-search-insns=200 --param max-sched-ready-insns=200 --param max-sched-region-insns=150 \
--param selsched-max-lookahead=75 --param max-delay-slot-insn-search=150 --param max-delay-slot-live-search=400 --param max-gcse-memory=268435456  --param max-partial-antic-length=150 --param max-tail-merge-iterations=3 \
--param max-tail-merge-comparisons=15 --param max-tracked-strlens=25000 --param inline-min-speedup=6 --param prefetch-latency=225 --param simultaneous-prefetches=4"
sched="-fmodulo-sched -fmodulo-sched-allow-regmoves -fsched2-use-superblocks -fsched-pressure -fsched-spec-load -fsched-spec-load-dangerous -fsched-stalled-insns=3 -fsched-stalled-insns-dep=100"
optim="-fpredictive-commoning -fmerge-all-constants -fdevirtualize-speculatively -fipa-cp-clone -minline-all-stringops -fivopts -ftracer -fipa-pta -fweb -frename-registers -fgcse-after-reload -fgcse-sm -fgcse-las -fno-semantic-interposition -fwrapv"
loops="-fprefetch-loop-arrays -funswitch-loops -fpeel-loops -funroll-loops -floop-nest-optimize -fvariable-expansion-in-unroller"
ftree="-ftree-vectorize -ftree-partial-pre -ftree-loop-linear -ftree-loop-im -ftree-loop-distribute-patterns -ftree-loop-if-convert-stores -ftree-loop-ivcanon -ftree-loop-distribution"
align="-falign-loops=16 -falign-functions=16" # -falign-jumps=16 -falign-labels=16"
lto="-flto -flto-partition=one -fdevirtualize-at-ltrans"

testing="-fbranch-target-load-optimize2"
# -maccumulate-outgoing-args -mno-push-args  .. one or the other


# Arch / cross-compiling specific
arch="-march=native -mtune=native"
#arch="-march=sandybridge -mtune=sandybridge"
static="OFF"


export CFLAGS="$general $protect $codegen $params $sched $optim $loops $ftree $align $arch $lto $testing"
cmake . -DCMAKE_LINK_STATIC="$static" -DHWLOC_ENABLE=OFF -DMICROHTTPD_ENABLE=OFF -DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_CXX_FLAGS="$CFLAGS" -DCMAKE_EXE_LINKER_FLAGS="$CFLAGS" -DCMAKE_C_FLAGS_RELEASE="-DNDEBUG" -DCMAKE_CXX_FLAGS_RELEASE="-DNDEBUG"

make -j2
