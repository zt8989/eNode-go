#!/bin/bash
set -e

# Spin up a throwaway MongoDB (plus mongo-express) for local testing of the
# mongodb storage engine. The container is ephemeral (--rm, no data volume): every
# start is a clean database. The engine self-provisions its collections and indexes
# on first connect (storage.MongoDBEngine.Init), and the enode database appears on
# the first write.

if [ ! -d "$PWD/scripts" ]; then
  echo "Please run this shell script from the project's root folder."
  exit 0
fi

MONGODB_PORT=37017
MONGO_EXPRESS_PORT=18081

case "$1" in
  stop)
    docker stop enode_mongoexpress 2>/dev/null || true
    docker stop enode_mongodb 2>/dev/null || true
    echo "MongoDB and mongo-express have been stopped."
    ;;
  *)
    docker run --rm -d \
      -p ${MONGODB_PORT}:27017 \
      --name enode_mongodb \
      mongo:7

    # Give mongod a moment to accept connections so mongo-express links on its
    # first attempt rather than crash-looping out of the --rm container.
    sleep 3

    docker run --rm -d \
      --name enode_mongoexpress \
      --link enode_mongodb:mongo \
      -p ${MONGO_EXPRESS_PORT}:8081 \
      -e ME_CONFIG_MONGODB_SERVER=mongo \
      -e ME_CONFIG_BASICAUTH_USERNAME=admin \
      -e ME_CONFIG_BASICAUTH_PASSWORD=admin \
      mongo-express:latest

    echo "MongoDB is running on localhost:${MONGODB_PORT} (no auth; database=enode created on first write)."
    echo "mongo-express: http://localhost:${MONGO_EXPRESS_PORT} (login admin / admin)"
    ;;
esac
