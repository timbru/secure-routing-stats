#!/bin/bash

# Exit on any error, e.g. bail out if downloading new sources fails
set -e

#
# This is script is meant to be run through cron by the stats
# user. It will get RPKI information, store it in a folder for
# today and run secure_routing_stats with the new information.
#
# It assumes that there is a local routinator instance running.
#
# The secure_routing_stats deamon will run because server side
# processing is needed to do scoped analysis - i.e. we could not
# just generate static content daily. This assumes that a proxy
# like nginx is set up to proxy requests to the service as well
# as serve the static 'sources' content which is archived daily.
#
# It is meant to be run once per day, if it is run more than once
# it will simply overwrite the previous information. It would be
# simple to change this - just include the time of day in DATA_SUB
# below - but there should be no need to run this more frequently.
#

RIS_v4_SOURCE="http://www.ris.ripe.net/dumps/riswhoisdump.IPv4.gz"
RIS_v6_SOURCE="http://www.ris.ripe.net/dumps/riswhoisdump.IPv6.gz"
NRO_SOURCE="https://www.nro.net/wp-content/uploads/apnic-uploads/delegated-extended"
VRPS_SOURCE="http://localhost:8323/csv"

# Create today's dir
BASE_DIR="/home/stats/sources"
DATE_SUB=`date +%Y/%m/%d`
DATE_DIR="$BASE_DIR/$DATE_SUB"

mkdir -p $DATE_DIR

# Set target locations for download and unpack
RIS_v4_GZ_TARGET="$DATE_DIR/ris-v4.txt.gz"
RIS_v4_TARGET="$DATE_DIR/ris-v4.txt"
RIS_v6_GZ_TARGET="$DATE_DIR/ris-v6.txt.gz"
RIS_v6_TARGET="$DATE_DIR/ris-v6.txt"
NRO_TARGET="$DATE_DIR/nro-stats.txt"
VRPS_TARGET="$DATE_DIR/vrps.csv"

WORLD_TEXT_TARGET="$DATE_DIR/world-stats.txt"
WORLD_JSON_TARGET="$DATE_DIR/world-stats.json"

# Download and unpack new sources
curl -s -o $RIS_v4_GZ_TARGET $RIS_v4_SOURCE 
curl -s -o $RIS_v6_GZ_TARGET $RIS_v6_SOURCE 
curl -s -L -o $NRO_TARGET $NRO_SOURCE
curl -s -o $VRPS_TARGET $VRPS_SOURCE

gunzip -f $RIS_v4_GZ_TARGET
gunzip -f $RIS_v6_GZ_TARGET

# Get world stats text and json
secure_routing_stats world --announcements $RIS_v4_TARGET $RIS_v6_TARGET --vrps $VRPS_TARGET --delegations $NRO_TARGET --format text > $WORLD_TEXT_TARGET
secure_routing_stats world --announcements $RIS_v4_TARGET $RIS_v6_TARGET --vrps $VRPS_TARGET --delegations $NRO_TARGET --format json > $WORLD_JSON_TARGET

# Restart the secure routing stats deamon - we need to RUN the deamon
# because it uses server side parsing to show details for specific resources
STATS_PID_FILE="/home/stats/secure-routing-stats.pid"

# Kill previous instance if it was running
if [[ -f "$STATS_PID_FILE" ]]; then
  kill `cat $STATS_PID_FILE` || true 
fi

# Run it again and save the PID
secure_routing_stats daemon --announcements $RIS_v4_TARGET $RIS_v6_TARGET --vrps $VRPS_TARGET --delegations $NRO_TARGET &
echo $! > $STATS_PID_FILE

# Now bzip the source files to save some space - they have already been read so this is safe
bzip2 -f $RIS_v4_TARGET
bzip2 -f $RIS_v6_TARGET
bzip2 -f $NRO_TARGET
bzip2 -f $VRPS_TARGET