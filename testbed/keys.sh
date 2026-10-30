#!/bin/bash
# Ключи стенда. Закрытые ключи остаются в $TB/keys/private (в репозиторий не попадают),
# открытые копируются в testbed/policy/keys и служат якорями доверия политики получателя.
#
# Роли: builder (сборочный агент), independent_builder (контрольная пересборка), vendor и vendor2
# (поставщик до и после смены ключа), repository (хранилище артефактов), sast, tester,
# attacker (ключи нарушителя для сценариев A1 и A6).
set -euo pipefail
TB=${TB:-/home/claude/tb}
HERE=$(cd "$(dirname "$0")" && pwd)
PRIV=$TB/keys/private PUB=$HERE/policy/keys
COSIGN=${COSIGN:-$TB/bin/cosign}
mkdir -p $PRIV $PUB
export COSIGN_PASSWORD=""

for role in builder independent_builder vendor vendor2 repository sast tester attacker; do
  if [ ! -f $PRIV/$role.key ]; then
    (cd $PRIV && $COSIGN generate-key-pair --output-key-prefix $role > /dev/null 2>&1)
  fi
  [ $role = attacker ] || cp $PRIV/$role.pub $PUB/$role.pub
done

# Ключи защищённой загрузки ArduPilot (EdDSA Monocypher, формат Tools/scripts/signing/generate_keys.py)
for who in vendor vendor2 attacker; do
  if [ ! -f $PRIV/${who}_private_key.dat ]; then
    (cd $PRIV && $TB/py311/bin/python $TB/ardupilot/Tools/scripts/signing/generate_keys.py $who > /dev/null)
  fi
  [ $who = attacker ] || cp $PRIV/${who}_public_key.dat $PUB/secure_boot_${who}.dat
done

# OpenPGP-ключи для подписи тегов: поставщик (в политике) и нарушитель (вне политики)
export GNUPGHOME=$TB/keys/gnupg
mkdir -p $GNUPGHOME && chmod 700 $GNUPGHOME
for who in vendor attacker; do
  uid="SCII testbed $who <$who@scii-testbed.invalid>"
  if ! gpg --batch --list-keys "$uid" > /dev/null 2>&1; then
    gpg --batch --pinentry-mode loopback --passphrase '' --quick-gen-key "$uid" ed25519 sign never 2> /dev/null
  fi
  gpg --batch --with-colons --list-keys "$uid" | awk -F: '/^fpr/ {print $10; exit}' > $PRIV/gpg_$who.fpr
done
gpg --batch --armor --export "vendor@scii-testbed.invalid" > $PUB/tag_signers.asc

(cd $PUB && sha256sum * > ../keys.SHA256SUMS)
echo "открытые ключи: $PUB"
cat $HERE/policy/keys.SHA256SUMS
echo "отпечаток ключа тегов поставщика: $(cat $PRIV/gpg_vendor.fpr)"
