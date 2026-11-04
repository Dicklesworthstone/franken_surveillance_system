#!/bin/bash
# Disable Tapo battery camera sleep via DS API
# Methods found in C660 firmware binary strings extraction:
#   battery_set_power_save {cur_status, power_save}
#   battery_set_power_supply_mode {power_supply_mode}
# Usage: disable_tapo_sleep.sh <camera_ip>

HOST="${1:?usage: disable_tapo_sleep.sh <ip>}"
DS="https://$HOST/"

echo "$(date) disabling sleep on $HOST"

# battery_set_power_save: keys from firmware strings (cur_status, power_save)
for BODY in \
  '{"method":"battery_set_power_save","params":{"power_save":{"enable":false}}}' \
  '{"method":"battery_set_power_save","params":{"power_save":false}}' \
  '{"method":"battery_set_power_save","params":{"cur_status":0,"power_save":0}}' \
  '{"method":"battery_set_power_save","params":{"power_save":{"mode":"wired_always_on"}}}' \
; do
  R=$(curl -sk -m 5 --interface en1 -X POST \
    -H "User-Agent: Tapo CameraClient Android" -H "Content-Type: application/json" \
    -d "$BODY" "$DS" 2>/dev/null | head -c 120)
  [ -n "$R" ] && echo "  $BODY → $R"
done

# battery_set_power_supply_mode: wired_always_on keeps camera awake on AC
for BODY in \
  '{"method":"battery_set_power_supply_mode","params":{"power_supply_mode":"wired_always_on"}}' \
  '{"method":"battery_set_power_supply_mode","params":{"mode":"wired_always_on"}}' \
  '{"method":"battery_set_power_supply_mode","params":{"power_supply_mode":0}}' \
; do
  R=$(curl -sk -m 5 --interface en1 -X POST \
    -H "User-Agent: Tapo CameraClient Android" -H "Content-Type: application/json" \
    -d "$BODY" "$DS" 2>/dev/null | head -c 120)
  [ -n "$R" ] && echo "  $BODY → $R"
done

echo "$(date) done"
