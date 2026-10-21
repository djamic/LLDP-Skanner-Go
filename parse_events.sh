#!/bin/bash

CSV="/home/qosim/Desktop/lldp_go/results/yesterday_24h/device_events.csv"

echo "=== Task 1: 4-Hour Intervals ==="
# We assume time is like 2026-04-10T08:15:30Z
awk -F',' '
    NR>1 && $8=="mac" {
        event = $10
        time_str = $6
        split(time_str, a, "T")
        split(a[2], b, ":")
        hour = int(b[1])
        
        if (hour >= 8 && hour < 12) intv = "08:00-12:00"
        else if (hour >= 12 && hour < 16) intv = "12:00-16:00"
        else if (hour >= 16 && hour < 20) intv = "16:00-20:00"
        else if (hour >= 20 && hour < 24) intv = "20:00-00:00"
        else intv = "00:00-08:00"
        
        counts[intv, event]++
    }
    END {
        print "08:00 - 12:00 : JOIN = " counts["08:00-12:00", "join"]+0 ", LEAVE = " counts["08:00-12:00", "leave"]+0
        print "12:00 - 16:00 : JOIN = " counts["12:00-16:00", "join"]+0 ", LEAVE = " counts["12:00-16:00", "leave"]+0
        print "16:00 - 20:00 : JOIN = " counts["16:00-20:00", "join"]+0 ", LEAVE = " counts["16:00-20:00", "leave"]+0
        print "20:00 - 00:00 : JOIN = " counts["20:00-00:00", "join"]+0 ", LEAVE = " counts["20:00-00:00", "leave"]+0
        print "00:00 - 08:00 : JOIN = " counts["00:00-08:00", "join"]+0 ", LEAVE = " counts["00:00-08:00", "leave"]+0
    }
' "$CSV"

echo ""
echo "=== Task 2: Peak Hours ==="
awk -F',' '
    NR>1 && $8=="mac" {
        time_str = $6
        split(time_str, a, "T")
        split(a[2], b, ":")
        
        # Lets group by 30-min intervals. HH:00 or HH:30
        hh = b[1]
        mm = int(b[2])
        if (mm < 30) {
            start_m = "00"
            end_m = "30"
            end_h = hh
        } else {
            start_m = "30"
            end_m = "00"
            end_h = sprintf("%02d", (int(hh)+1)%24)
        }
        
        t_block = hh ":" start_m " - " end_h ":" end_m
        if ($10=="join" || $10=="leave") {
            blocks[t_block]++
        }
    }
    END {
        for (b in blocks) print b " => " blocks[b] " events"
    }
' "$CSV" | sort -t'>' -k2 -nr | head -n 5

echo ""
echo "=== Task 3: Long-term Offline Devices ==="
awk -F',' '
    NR>1 && $8=="mac" {
        mac = $7
        event = $10
        time_str = $6
        
        # track the last event seen for each MAC
        last_event[mac] = event
        
        # also track if it ever joined
        if (event == "join") has_joined[mac] = 1
        if (event == "leave") has_left[mac] = 1
    }
    END {
        offline_last = 0
        left_never_joined = 0
        total_macs = 0
        for (m in last_event) {
            total_macs++
            if (last_event[m] == "leave") offline_last++
            if (has_left[m] == 1 && has_joined[m] != 1) left_never_joined++
        }
        print "Jami eventda qatnashgan MAC lar (total tracking pool):", total_macs
        print "Oxirgi statusi LEAVE bolgan kompyuterlar/qurilmalar:", offline_last
        print "Tarixda LEAVE bolgan, lekin uzluksiz kirmagan (Dead):", left_never_joined
    }
' "$CSV"

