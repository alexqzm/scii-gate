#!/bin/bash
# Окружение стенда: Python 3.11, тулчейн ArduPilot для STM32, cosign, клон ArduPilot по тегу с подмодулями.
# Все загрузки сверяются с закреплёнными SHA-256. Рабочий каталог $TB находится вне репозитория.
set -euo pipefail
TB=${TB:-/home/claude/tb}
TAG=${TAG:-Copter-4.5.7}
COMMIT=${COMMIT:-2a3dc4b7bf2507120f7378a7b2fde73185e0c325}
TC=gcc-arm-none-eabi-10-2020-q4-major
TC_SHA256=21134caa478bbf5352e239fbc6e2da3038f8d2207e089efc96c3b55f1edcd618
COSIGN_SHA256=8b24b946dd5809c6bd93de08033bcf6bc0ed7d336b7785787c080f574b89249b   # cosign v2.4.1 linux-amd64
HERE=$(cd "$(dirname "$0")" && pwd)
mkdir -p $TB/logs $TB/bin $TB/toolchain

# 1. Python 3.11: pymonocypher 3.1.3.2 и empy 3.3.4, которые требует ArduPilot 4.5, рассчитаны на него
if [ ! -x $TB/py311/bin/python ]; then
  command -v uv > /dev/null || python3 -m pip install -q --user uv
  uv python install 3.11
  uv venv --python 3.11 $TB/py311
  VIRTUAL_ENV=$TB/py311 uv pip install -q --require-hashes -r $HERE/../ci/requirements-ardupilot.txt
  VIRTUAL_ENV=$TB/py311 uv pip install -q pytest flawfinder==2.0.20
fi

# 2. Тулчейн, который задаёт Tools/environment_install/install-prereqs-ubuntu.sh тега
if [ ! -x $TB/toolchain/$TC/bin/arm-none-eabi-gcc ]; then
  curl -sSfL -o $TB/toolchain/tc.tar.bz2 https://firmware.ardupilot.org/Tools/STM32-tools/$TC-x86_64-linux.tar.bz2
  echo "$TC_SHA256  $TB/toolchain/tc.tar.bz2" | sha256sum -c -
  tar xjf $TB/toolchain/tc.tar.bz2 -C $TB/toolchain && rm $TB/toolchain/tc.tar.bz2
fi

# 3. cosign
if [ ! -x $TB/bin/cosign ]; then
  curl -sSfL -o $TB/bin/cosign https://github.com/sigstore/cosign/releases/download/v2.4.1/cosign-linux-amd64
  echo "$COSIGN_SHA256  $TB/bin/cosign" | sha256sum -c -
  chmod +x $TB/bin/cosign
fi

# 4. ArduPilot по тегу и проверка коммита
if [ ! -d $TB/ardupilot ]; then
  git clone -q --depth 1 --branch $TAG https://github.com/ArduPilot/ardupilot.git $TB/ardupilot
  test "$(git -C $TB/ardupilot rev-parse HEAD)" = "$COMMIT"
  cd $TB/ardupilot
  git submodule update -q --init --depth 1 modules/waf modules/mavlink modules/ChibiOS modules/DroneCAN/DSDL \
      modules/DroneCAN/pydronecan modules/DroneCAN/dronecan_dsdlc modules/DroneCAN/libcanard modules/lwip
  git submodule update -q --init --recursive --depth 1 modules/CrashDebug
fi
# 5. Сценарий подписи прошивки: в теге он не запускается (SyntaxError), берётся из master по закреплённому коммиту
if [ ! -f $TB/tools/make_secure_fw.py ]; then
  mkdir -p $TB/tools && rm -rf $TB/tools/ap-master.git
  git init -q --bare $TB/tools/ap-master.git
  git -C $TB/tools/ap-master.git remote add origin https://github.com/ArduPilot/ardupilot.git
  git -C $TB/tools/ap-master.git fetch -q --depth 1 --filter=blob:none origin 278a68a57aa0d9b98e6dbaaf9346f6b485f4c9ac
  git -C $TB/tools/ap-master.git show 278a68a57aa0d9b98e6dbaaf9346f6b485f4c9ac:Tools/scripts/signing/make_secure_fw.py \
      > $TB/tools/make_secure_fw.py
  test "$(git hash-object $TB/tools/make_secure_fw.py)" = f72cfdf34a94d2a012745a7cb63252db84ee5478
fi
git -C $TB/ardupilot submodule status --recursive > $TB/logs/submodules.txt
echo "окружение стенда готово: $TB"
