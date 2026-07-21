#!/bin/bash
set -e

# Spin up a throwaway MariaDB (plus phpMyAdmin) for local testing of the mysql
# storage engine. The container is ephemeral (--rm, no data volume): every start
# is a clean database. The server creates the schema on first connect
# (storage.MySQLEngine.Init reads misc/enode.sql), so nothing is mounted here.

if [ ! -d "$PWD/scripts" ]; then
  echo "Please run this shell script from the project's root folder."
  exit 0
fi

MARIADB_PORT=13306
PMA_PORT=18080

case "$1" in
  stop)
    docker stop enode_phpmyadmin 2>/dev/null || true
    docker stop enode_mariadb 2>/dev/null || true
    echo "MariaDB and phpMyAdmin have been stopped."
    ;;
  *)
    docker run --rm -d \
      -p ${MARIADB_PORT}:3306 \
      --name enode_mariadb \
      -e MARIADB_ROOT_PASSWORD=root \
      -e MARIADB_DATABASE=enode \
      -e MARIADB_USER=enode \
      -e MARIADB_PASSWORD=password \
      mariadb:lts \
      --character-set-server=utf8mb4 --collation-server=utf8mb4_unicode_ci

    docker run --rm -d \
      --name enode_phpmyadmin \
      --link enode_mariadb:db \
      -p ${PMA_PORT}:80 \
      -e PMA_SESSION_EXPIRATION=86400 \
      phpmyadmin:latest

    echo "MariaDB is running on localhost:${MARIADB_PORT} (database=enode user=enode pass=password)."
    echo "Tables are created automatically the first time the server connects with engine: mysql."
    echo "phpMyAdmin: http://localhost:${PMA_PORT} (server db, user enode / pass password, or root / root)"
    ;;
esac
