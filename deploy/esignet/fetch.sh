#!/bin/sh
# Take the two files this rig borrows from MOSIP's eSignet repository, at the
# commit it was checked against, and refuse them if they are not the bytes that
# were checked: the database seed and the proxy in front of the sign-in page.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
commit=36e3514c24c0396418767a523ba6142c877fe1d3
base="https://raw.githubusercontent.com/mosip/esignet/$commit/docker-compose"

digest() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

fetch() {
  name=$1
  expected=$2
  target="$here/upstream/$name"
  if [ -f "$target" ] && [ "$(digest "$target")" = "$expected" ]; then
    return
  fi
  curl -fsSL "$base/$name" -o "$target.part"
  found=$(digest "$target.part")
  if [ "$found" != "$expected" ]; then
    rm -f "$target.part"
    echo "$name is not the file this rig was checked against ($found)" >&2
    exit 1
  fi
  mv "$target.part" "$target"
}

mkdir -p "$here/upstream"
fetch init.sql 1823da061189046dd6329c87576426d39c268118b9aa90f8d3498f9d9276e1a9
fetch nginx.conf c0e82870b0fcb8adb7f53ece43ed7951b64bbd60ccdf82021c01aeb7a4468084
echo "upstream files in place"
