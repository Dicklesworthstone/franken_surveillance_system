#!/bin/bash
# Disable Tapo battery camera sleep mode via DS API
# Uses the battery_set_power_supply_mode / battery_set_power_save methods
# found in the C660 firmware binary (strings extraction)
# Usage: disable_tapo_sleep.sh <camera_ip>

HOST="${1:?usage: disable_tapo_sleep.sh <ip>}"
DS="https://$HOST/"

echo "$(date) attempting to disable sleep on $HOST"

# Try multiple method/param combinations (the exact schema is inferred from firmware strings)
for METHOD in "battery_set_power_supply_mode" "battery_set_power_save"; do
  for PARAMS in '{"power_supply_mode":"wired_always_on"}' '{"power_save":0}' '{"power_save_mode":"off"}' '{"enable":0}' '{}'; do
    R=$(curl -sk -m 5 --interface en1 -X POST \
      -H "User-Agent: Tapo CameraClient Android" -H "Content-Type: application/json" \
      -d "{\"method\":\"$METHOD\",\"params\":$PARAMS}" "$DS" 2>/dev/null | head -c 120)
    if [ -n "$R" ]; then
      echo "  $METHOD $PARAMS → $R"
    fi
  done
done
echo "$(date) done"
