#!/bin/bash
set -e

# Convenience wrapper: start (or stop) both test databases at once.
#   ./scripts/docker-testdb.sh        # start MariaDB + MongoDB (and their admin UIs)
#   ./scripts/docker-testdb.sh stop   # stop all four containers

if [ ! -d "$PWD/scripts" ]; then
  echo "Please run this shell script from the project's root folder."
  exit 0
fi

"$PWD/scripts/docker-mariadb.sh" "$1"
"$PWD/scripts/docker-mongodb.sh" "$1"
