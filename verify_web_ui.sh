#!/bin/bash
# Verify that frontend files contain the expected changes

echo "🔍 Checking index.html..."
if grep -q "startCapture()" static/index.html; then
    echo "✅ index.html: Start Capture button found"
else
    echo "❌ index.html: Start Capture button NOT found"
    exit 1
fi

echo "🔍 Checking app.js..."
if grep -q "function startCapture()" static/app.js; then
    echo "✅ app.js: startCapture function found"
else
    echo "❌ app.js: startCapture function NOT found"
    exit 1
fi

echo "🔍 Checking style.css..."
if grep -q ".capture-btn" static/style.css; then
    echo "✅ style.css: .capture-btn style found"
else
    echo "❌ style.css: .capture-btn style NOT found"
    exit 1
fi

echo "✅ Web UI Verification Complete"
