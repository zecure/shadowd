#!/bin/bash
set -e

SHADOWD_CONFIG="/etc/shadowd/shadowd.ini"

cat /dev/null > $SHADOWD_CONFIG

if [ -n "$SHADOWD_ADDRESS" ]; then
    echo "address=$SHADOWD_ADDRESS" >> $SHADOWD_CONFIG
fi

if [ -n "$SHADOWD_THREADS" ]; then
    echo "threads=$SHADOWD_THREADS" >> $SHADOWD_CONFIG
fi

if [ -n "$SHADOWD_DB_DRIVER" ]; then
    echo "db-driver=$SHADOWD_DB_DRIVER" >> $SHADOWD_CONFIG
fi

if [ -n "$SHADOWD_DB_HOST" ]; then
    echo "db-host=$SHADOWD_DB_HOST" >> $SHADOWD_CONFIG
fi

if [ -n "$SHADOWD_DB_PORT" ]; then
    echo "db-port=$SHADOWD_DB_PORT" >> $SHADOWD_CONFIG
fi

if [ -n "$SHADOWD_DB_NAME" ]; then
    echo "db-name=$SHADOWD_DB_NAME" >> $SHADOWD_CONFIG
fi

if [ -n "$SHADOWD_DB_USER" ]; then
    echo "db-user=$SHADOWD_DB_USER" >> $SHADOWD_CONFIG
fi

if [ -n "$SHADOWD_DB_PASSWORD" ]; then
    echo "db-password=$SHADOWD_DB_PASSWORD" >> $SHADOWD_CONFIG
fi

sleep 15
echo "Starting command $@"
exec "$@"

