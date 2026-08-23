#!/bin/sh
# Prepare the mounted volume, then hand off. Kept out of the Dockerfile because the
# volume does not exist at build time -- Fly attaches it to the machine at boot.
set -e

mkdir -p "$(dirname "${BEAMLINE_DB:-/data/beamline.db}")" "${BEAMLINE_POOL_DIR:-/data/pool}"
chown -R beamline:beamline /data 2>/dev/null || true

# Fail loudly and early rather than serving a beacon nobody can attribute. The service
# refuses to start without this anyway; catching it here makes the reason obvious in
# `fly logs` instead of buried in a Python traceback.
if [ -z "$BEAMLINE_BEACON_KEY" ] && [ -z "$BEAMLINE_ALLOW_UNSIGNED_BEACON" ]; then
  echo "FATAL: BEAMLINE_BEACON_KEY is not set." >&2
  echo "  Generate one with: beamline beacon-key" >&2
  echo "  Then:              fly secrets set BEAMLINE_BEACON_KEY=..." >&2
  exit 1
fi

# setpriv rather than su: su -c re-parses its arguments through a shell, which mangles
# anything containing spaces and makes $0/$@ handling depend on which su is installed.
# setpriv (util-linux, present in the slim base) execs directly with no shell in between.
exec setpriv --reuid=10001 --regid=10001 --init-groups "$@"
