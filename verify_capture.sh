#!/bin/bash
set -e

BASE_URL="http://localhost:8080/api"

echo "waiting for server..."
sleep 2

# 1. Start Capture
echo "🚀 Starting Capture..."
START_RESP=$(curl -s -X POST "${BASE_URL}/capture/start?name=TestSession")
echo "Start Response: $START_RESP"
SESSION_ID=$(echo $START_RESP | grep -o '"session_id":"[^"]*"' | cut -d'"' -f4)

if [ -z "$SESSION_ID" ]; then
    echo "❌ Failed to get Session ID"
    exit 1
fi
echo "✅ Session ID: $SESSION_ID"

# 2. Simulate wait
echo "⏳ Waiting 5 seconds..."
sleep 5

# 3. Stop Capture
echo "🛑 Stopping Capture..."
STOP_RESP=$(curl -s -X POST "${BASE_URL}/capture/stop")
echo "Stop Response: $STOP_RESP"

# 4. List Captures
echo "📂 Listing Captures..."
LIST_RESP=$(curl -s "${BASE_URL}/captures")
echo "List Response: $LIST_RESP"

# 5. Generate Report
echo "📊 Generating Report..."
REPORT_RESP=$(curl -s -X POST "${BASE_URL}/report/generate?id=${SESSION_ID}")
echo "Report generated (length: ${#REPORT_RESP} chars)"

echo "✅ VERIFICATION COMPLETE"
