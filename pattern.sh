#!/bin/sh
set -eu
cd "$(dirname "$0")"
if [ "${1:-}" != make ]; then
  echo 'Usage: ./pattern.sh make <target> [VALUES=site.yaml]' >&2; exit 2
fi
shift
exec make "$@"
