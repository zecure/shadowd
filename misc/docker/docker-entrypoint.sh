#!/bin/bash
set -e

SHADOWD_CONFIG="/etc/shadowd/shadowd.ini"

remove_newline () {
    echo "$1" | sed -e 's/[\r\n]//g'
}

reset_config () {
    cat /dev/null > $SHADOWD_CONFIG
}

set_value () {
   CONFIG_KEY=$(remove_newline $1)
   CONFIG_VALUE=$(remove_newline $2)

   if [ -n "$CONFIG_VALUE" ]; then
       echo "$CONFIG_KEY=$CONFIG_VALUE" >> $SHADOWD_CONFIG
   fi
}

reset_config
set_value address $SHADOWD_ADDRESS
set_value threads $SHADOWD_THREADS
set_value db-driver $SHADOWD_DB_DRIVER
set_value db-host $SHADOWD_DB_HOST
set_value db-port $SHADOWD_DB_PORT
set_value db-name $SHADOWD_DB_NAME
set_value db-user $SHADOWD_DB_USER
set_value db-password $SHADOWD_DB_PASSWORD

echo "Starting command $@"
exec "$@"

