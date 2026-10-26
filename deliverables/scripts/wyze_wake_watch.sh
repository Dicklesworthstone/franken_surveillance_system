#!/bin/sh
# Fire the OTA chain the moment a sleeping unit answers.
#
# The cameras sleep and only wake on their own schedule, so polling by hand wastes the window. This
# watches for the unit to answer, then breaks its cloud session so it reconnects to our broker, where
# the injector already runs on every connection. It also re-arms the broker if the injector gave up.
#
#   wyze_wake_watch.sh <ip> [seconds]
set -u
IP=${1:?ip}
SECS=${2:-3600}
END=$(( $(date +%s) + SECS ))
was_down=1
while [ "$(date +%s)" -lt "$END" ]; do
  if ping -c 1 -W 800 "$IP" >/dev/null 2>&1; then
    if [ "$was_down" -eq 1 ]; then
      echo "$(date +%H:%M:%S) $IP awake"
      was_down=0
      sudo -n launchctl kickstart -k system/com.jeffreyemanuel.wyze-broker >/dev/null 2>&1
      sleep 3
    fi
    # break the real-cloud session so the device reconnects to us
    sudo -n timeout 12 python3 /tmp/rst.py "$IP" 10 >/dev/null 2>&1
    sleep 8
  else
    [ "$was_down" -eq 0 ] && echo "$(date +%H:%M:%S) $IP asleep"
    was_down=1
    sleep 10
  fi
done
