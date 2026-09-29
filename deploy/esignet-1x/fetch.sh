#!/bin/sh
# Take the two files this rig borrows from MOSIP's eSignet repository, at the
# commit it was checked against, and refuse them if they are not the bytes that
# were checked: the database seed and the proxy in front of the sign-in page.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
commit=1d66d18b1571672f4c05acb8be0cd8e64a20e9ad
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
fetch init.sql 9d9f6df18232e08ac3afc06f292e34eb2cc12ef491d0f235ad74b2e892f6ea90
fetch nginx.conf b72aab48d312b613cb38150ccb7f2926246e550154604eb2525353ef60fc996c
echo "upstream files in place"
