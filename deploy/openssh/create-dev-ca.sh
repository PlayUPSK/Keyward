#!/usr/bin/env sh
set -eu

out_dir="${1:-platform/dev_ca}"
mkdir -p "$out_dir"

if [ -f "$out_dir/ssh_user_ca" ]; then
  echo "CA already exists: $out_dir/ssh_user_ca"
  exit 0
fi

ssh-keygen -q -t ed25519 -N "" -C "keyward-dev-user-ca" -f "$out_dir/ssh_user_ca"
echo "created dev SSH user CA at $out_dir/ssh_user_ca"
