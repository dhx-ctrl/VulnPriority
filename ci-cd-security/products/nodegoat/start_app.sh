#!/usr/bin/env bash
# start_app.sh — Start NodeGoat with its MongoDB sidecar for ZAP scanning.
#
# Sourced by run_pipeline.sh.
# Expects: APP_NAME, APP_URL, APP_PORT, DOCKER_IMAGE_NAME
#
# NodeGoat specifics:
#   • Requires MongoDB to be running and reachable.
#   • The Dockerfile doesn't start the app correctly by itself — the
#     official compose flow waits for MongoDB, seeds the DB, then runs
#     npm start.  We replicate that with a shell entrypoint command.

set -euo pipefail

###############################################################################
#  Start MongoDB
###############################################################################

docker pull mongo:4.4
docker rm -f "mongo-${APP_NAME}" 2>/dev/null || true

docker run -d \
  --name "mongo-${APP_NAME}" \
  --network zapnet \
  --network-alias "mongo-${APP_NAME}" \
  --network-alias mongo \
  mongo:4.4

echo "Waiting for MongoDB to accept connections..."
for i in {1..30}; do
  if docker exec "mongo-${APP_NAME}" mongo --eval "db.runCommand({ping:1})" --quiet >/dev/null 2>&1; then
    echo "MongoDB ready after ${i}×2s"
    break
  fi
  if [[ $i -eq 30 ]]; then
    echo "ERROR: MongoDB did not become ready"
    docker logs "mongo-${APP_NAME}" --tail 100 || true
    return 1
  fi
  sleep 2
done

###############################################################################
#  Start NodeGoat
###############################################################################

docker rm -f "target-${APP_NAME}" 2>/dev/null || true
docker pull curlimages/curl:8.6.0

docker run -d \
  --name "target-${APP_NAME}" \
  --network zapnet \
  --network-alias "target-${APP_NAME}" \
  -e "PORT=${APP_PORT}" \
  -e "MONGODB_URI=mongodb://mongo-${APP_NAME}:27017/nodegoat" \
  -p "${APP_PORT}:${APP_PORT}" \
  "$DOCKER_IMAGE_NAME" \
  sh -c "until nc -z -w 2 mongo-${APP_NAME} 27017 && echo 'mongo is ready' && node artifacts/db-reset.js && npm start; do echo 'waiting for mongo / db seed...'; sleep 2; done"
