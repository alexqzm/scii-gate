#!/bin/bash
# Стенд SCII: сборки ArduPilot для испытаний гейта.
#
#   builds.sh all          очередь сборок по порядку (каждый шаг пропускается, если уже выполнен)
#   builds.sh <шаг>        один шаг: signed, signed-r, indep, sitl, A5, A3, A7, old
#
# Все шаги пишут продукты в $TB/products/<шаг>/ и строку времени в $TB/logs/timing.txt.
# Окружение (Python 3.11, тулчейн, клон ArduPilot) готовит setup.sh.
set -euo pipefail
TB=${TB:-/home/claude/tb}
TAG=${TAG:-Copter-4.5.7}
OLD_TAG=${OLD_TAG:-Copter-4.5.5}
SRC=$TB/ardupilot
TOOLCHAIN=$TB/toolchain/gcc-arm-none-eabi-10-2020-q4-major/bin
export PATH=$TOOLCHAIN:$TB/py311/bin:$PATH
mkdir -p $TB/products $TB/logs
ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
SUBMODULES="modules/waf modules/mavlink modules/ChibiOS modules/DroneCAN/DSDL modules/DroneCAN/pydronecan \
modules/DroneCAN/dronecan_dsdlc modules/DroneCAN/libcanard modules/lwip"

save() {  # save NAME OUTDIR: копирует продукты сборки и пишет их SHA-256
  local name=$1 out=$2 d=$TB/products/$1
  mkdir -p $d
  cp $out/CubeOrange/bin/arducopter.bin $out/CubeOrange/bin/arducopter.apj $d/
  (cd $d && sha256sum arducopter.bin arducopter.apj > SHA256SUMS)
  echo "[$(ts)] $name: $(cut -c1-16 $d/SHA256SUMS | tr '\n' ' ')"
}

build() {  # build SRC OUT NAME [опции configure]
  local src=$1 out=$2 name=$3; shift 3
  ( cd $src; SECONDS=0
    ./waf configure --board CubeOrange "$@" --out $out > $TB/logs/configure-$name.log 2>&1
    ./waf copter --out $out -j $(nproc) > $TB/logs/build-$name.log 2>&1
    echo "$name: ${SECONDS}s (configure+build, $(nproc) ядра)" >> $TB/logs/timing.txt )
}

rebuild() {  # инкрементальная сборка в существующем каталоге
  local src=$1 out=$2 name=$3
  ( cd $src; SECONDS=0
    ./waf copter --out $out -j $(nproc) > $TB/logs/build-$name.log 2>&1
    echo "$name: ${SECONDS}s (инкрементальная)" >> $TB/logs/timing.txt )
}

clone() {  # clone DIR TAG: независимый клон тега с теми же подмодулями
  local dir=$1 tag=$2
  rm -rf $dir; mkdir -p $(dirname $dir)
  git clone -q --depth 1 --branch $tag https://github.com/ArduPilot/ardupilot.git $dir
  ( cd $dir; git submodule update -q --init --depth 1 $SUBMODULES
    git submodule update -q --init --recursive --depth 1 modules/CrashDebug
    git rev-parse HEAD > COMMIT.txt; git submodule status --recursive > SUBMODULES.txt )
}

check_same() {  # после отката изменения образ должен вернуться к исходному
  local a=$(cut -d' ' -f1 <(grep arducopter.bin $TB/products/signed/SHA256SUMS))
  local b=$(sha256sum $SRC/build-signed/CubeOrange/bin/arducopter.bin | cut -d' ' -f1)
  if [ "$a" = "$b" ]; then echo "$1: возврат к исходному образу подтверждён" | tee -a $TB/logs/timing.txt
  else echo "$1: ОБРАЗ НЕ ВЕРНУЛСЯ К ИСХОДНОМУ ($b)" | tee -a $TB/logs/timing.txt; exit 1; fi
}

marker() {  # marker FILE OLD NEW: инертная правка строки сообщения (модель внедрения)
  $TB/py311/bin/python - "$@" <<'EOF'
import sys
path, old, new = sys.argv[1:4]
s = open(path, encoding="utf-8").read()
assert s.count(old) == 1, "строка не найдена или неоднозначна"
open(path, "w", encoding="utf-8").write(s.replace(old, new))
EOF
}

step() {
  local s=$1
  [ -f $TB/products/$s/DONE ] && { echo "$s: уже выполнен"; return; }
  echo "[$(ts)] шаг $s"
  case $s in
    signed)    build $SRC $SRC/build-signed signed --signed-fw; save signed $SRC/build-signed ;;
    signed-r)  build $SRC $SRC/build-signed-r signed-r --signed-fw; save signed-r $SRC/build-signed-r ;;
    indep)     clone $TB/indep/ardupilot $TAG
               build $TB/indep/ardupilot $TB/indep/ardupilot/build-signed indep --signed-fw
               save indep $TB/indep/ardupilot/build-signed
               cp $TB/indep/ardupilot/COMMIT.txt $TB/indep/ardupilot/SUBMODULES.txt $TB/products/indep/ ;;
    sitl)      ( cd $SRC; SECONDS=0
                 ./waf configure --board sitl --out $SRC/build-sitl > $TB/logs/configure-sitl.log 2>&1
                 ./waf copter --out $SRC/build-sitl -j $(nproc) > $TB/logs/build-sitl.log 2>&1
                 echo "sitl: ${SECONDS}s" >> $TB/logs/timing.txt )
               mkdir -p $TB/products/sitl; cp $SRC/build-sitl/sitl/bin/arducopter $TB/products/sitl/
               (cd $TB/products/sitl && sha256sum arducopter > SHA256SUMS) ;;
    A5|A3)     # A5: внедрение на сборочном агенте; A3: архив исходников отличается от git (как в xz)
               local f=ArduCopter/Parameters.cpp old='"load_all took %uus\n"'
               local new='"load_all took %uus [SCII-'$s']\n"'
               ( cd $SRC; marker $f "$old" "$new"; git diff > $TB/logs/$s.patch )
               if [ $s = A3 ]; then
                 ( cd $SRC; git archive --format=tar --prefix=ardupilot-$TAG/ HEAD > $TB/products/A3-src.tar
                   tar --delete -f $TB/products/A3-src.tar ardupilot-$TAG/$f
                   tar --append -f $TB/products/A3-src.tar --transform "s,^,ardupilot-$TAG/," \
                       --mtime="@$(git log -1 --format=%ct)" --owner=0 --group=0 --numeric-owner $f
                   gzip -n -9 -f $TB/products/A3-src.tar )
               fi
               rebuild $SRC $SRC/build-signed $s; save $s $SRC/build-signed
               ( cd $SRC; git checkout -- $f ); rebuild $SRC $SRC/build-signed $s-revert; check_same $s ;;
    A7)        # подмена зависимости: libcanard на родительском коммите вместо закреплённого
               local m=$SRC/modules/DroneCAN/libcanard pin
               pin=$(git -C $m rev-parse HEAD)
               git -C $m fetch -q --depth 2 origin $pin; git -C $m checkout -q HEAD~1
               git -C $m rev-parse HEAD > $TB/logs/A7.libcanard; git -C $m diff --stat $pin HEAD >> $TB/logs/A7.libcanard
               rebuild $SRC $SRC/build-signed A7; save A7 $SRC/build-signed
               (cd $SRC && git submodule status modules/DroneCAN/libcanard > $TB/products/A7/SUBMODULE.txt)
               git -C $m checkout -q $pin; rebuild $SRC $SRC/build-signed A7-revert; check_same A7 ;;
    old)       clone $TB/old/ardupilot $OLD_TAG
               build $TB/old/ardupilot $TB/old/ardupilot/build-signed old --signed-fw
               save old $TB/old/ardupilot/build-signed
               cp $TB/old/ardupilot/COMMIT.txt $TB/old/ardupilot/SUBMODULES.txt $TB/products/old/ ;;
    *) echo "неизвестный шаг $s"; exit 2 ;;
  esac
  touch $TB/products/$s/DONE 2>/dev/null || { mkdir -p $TB/products/$s; touch $TB/products/$s/DONE; }
}

if [ "${1:-}" = all ]; then
  for s in signed A5 A3 A7 signed-r indep sitl old; do step $s; done
  echo "[$(ts)] очередь сборок завершена"
else
  step "$1"
fi
