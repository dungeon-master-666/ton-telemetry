#!/bin/bash
set -e

MONGODB_PASSWORD=$(cat /home/toncenter/ton-telemetry/private/mongodb_password)
COMMAND="exec mongodump -u user1 -p $MONGODB_PASSWORD -d telemetry --authenticationDatabase admin --archive"

docker exec ton-telemetry_mongodb_1 sh -c "$COMMAND" > /var/ton-backup/telemetry.archive
