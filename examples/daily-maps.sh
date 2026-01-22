#!/bin/bash

# Exit on any error, e.g. bail out if downloading new sources fails
set -e

# Local config
BASE_DIR="/Users/tbruijnzeels/Development/secure-routing-stats/sources"
STATS_BIN="/Users/tbruijnzeels/checkouts/secure-routing-stats/target/release/secure_routing_stats"

#
# This is script is meant to be run through cron by the stats
# user. It will get RPKI information, store it in a folder for
# today and run secure_routing_stats with the new information.
#
# The secure_routing_stats deamon will run because server side
# processing is needed to do scoped analysis - i.e. we could not
# just generate static content daily. This assumes that a proxy
# like nginx is set up to proxy requests to the service as well
# as serve the static 'sources' content which is archived daily.
#
# It is meant to be run once per day, if it is run more than once
# it will simply skip existing files and outputs, and just restart
# the daemon. Clean up the source dir files of the day to have a
# clean restart.
#

# Sources
RIS_v4_SOURCE="http://www.ris.ripe.net/dumps/riswhoisdump.IPv4.gz"
RIS_v6_SOURCE="http://www.ris.ripe.net/dumps/riswhoisdump.IPv6.gz"
NRO_SOURCE="https://www.nro.net/wp-content/uploads/apnic-uploads/delegated-extended"
RPKI_STATS_SOURCE="https://rpki-validator.ripe.net/json"

# Create today's dir
DATE_SUB=`date +%Y/%m/%d`
DATE_DIR="$BASE_DIR/$DATE_SUB"

mkdir -p $DATE_DIR

# Set target locations for download and unpack
RIS_v4_GZ_TARGET="$DATE_DIR/ris-v4.txt.gz"
RIS_v4_TARGET="$DATE_DIR/ris-v4.txt"
RIS_v6_GZ_TARGET="$DATE_DIR/ris-v6.txt.gz"
RIS_v6_TARGET="$DATE_DIR/ris-v6.txt"
NRO_TARGET="$DATE_DIR/nro-stats.txt"
RPKI_STATS_TARGET="$DATE_DIR/rpki-stats.json"

WORLD_TEXT_TARGET="$DATE_DIR/world-stats.txt"
WORLD_JSON_TARGET="$DATE_DIR/world-stats.json"
ASPA_TEXT_TARGET="$DATE_DIR/world-aspa.csv"

# Download and unpack new sources
[ -f $RIS_v4_TARGET ] || curl -s -o $RIS_v4_GZ_TARGET $RIS_v4_SOURCE 
[ -f $RIS_v6_TARGET ] || curl -s -o $RIS_v6_GZ_TARGET $RIS_v6_SOURCE 
[ -f $NRO_TARGET ] || curl -s -L -o $NRO_TARGET $NRO_SOURCE
[ -f $RPKI_STATS_TARGET ] || curl -s -o $RPKI_STATS_TARGET $RPKI_STATS_SOURCE

[ -f $RIS_v4_GZ_TARGET ] && gunzip -f $RIS_v4_GZ_TARGET
[ -f $RIS_v6_GZ_TARGET ] && gunzip -f $RIS_v6_GZ_TARGET

# Get world stats text and json
[ -f  $WORLD_TEXT_TARGET ] || $STATS_BIN world --announcements $RIS_v4_TARGET $RIS_v6_TARGET --rpki $RPKI_STATS_TARGET --delegations $NRO_TARGET --format text > $WORLD_TEXT_TARGET
[ -f $WORLD_JSON_TARGET ] || $STATS_BIN world --announcements $RIS_v4_TARGET $RIS_v6_TARGET --rpki $RPKI_STATS_TARGET --delegations $NRO_TARGET --format json > $WORLD_JSON_TARGET

# Get world ASPA CSV
[ -f $ASPA_TEXT_TARGET ] || $STATS_BIN aspa --rpki $RPKI_STATS_TARGET --delegations $NRO_TARGET > $ASPA_TEXT_TARGET

# Restart the secure routing stats deamon - we need to RUN the deamon
# because it uses server side parsing to show details for specific resources
STATS_PID_FILE="$BASE_DIR/secure-routing-stats.pid"

# Kill previous instance if it was running
if [[ -f "$STATS_PID_FILE" ]]; then
  if [[ "$(ps -ef | grep `cat $STATS_PID_FILE` | grep -v grep)" ]]; then
    kill `cat $STATS_PID_FILE` || true
  fi
fi

# Run it again and save the PID
$STATS_BIN daemon --announcements $RIS_v4_TARGET $RIS_v6_TARGET --rpki $RPKI_STATS_TARGET --delegations $NRO_TARGET &
echo $! > $STATS_PID_FILE

# # Now bzip the source files to save some space - they have already been read so this is safe
# bzip2 -f $RIS_v4_TARGET
# bzip2 -f $RIS_v6_TARGET
# bzip2 -f $NRO_TARGET
# bzip2 -f $RPKI_STATS_TARGET
