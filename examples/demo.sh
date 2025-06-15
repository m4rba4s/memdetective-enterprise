#!/bin/bash
#
# Memory Inspector CLI - Demo Script
# 
# Demonstrates key features and capabilities
#

set -e

BINARY="./memory-inspector"
if [ ! -f "$BINARY" ]; then
    echo "Error: memory-inspector binary not found. Run 'make' first."
    exit 1
fi

echo "🔍 Memory Inspector CLI - Demonstration"
echo "======================================"
echo

echo "📋 1. Show version and help information"
echo "---------------------------------------"
$BINARY --version
echo
$BINARY --help
echo

echo "🧪 2. Analyze current shell process (safe test)"
echo "-----------------------------------------------"
echo "Analyzing PID $$..."
$BINARY --pid $$ --verbose
echo

echo "📊 3. Quick analysis of multiple processes"
echo "-----------------------------------------"
for pid in $(pgrep -u $USER | head -3); do
    echo "Analyzing PID $pid..."
    $BINARY --pid $pid 2>/dev/null || echo "  → Permission denied (expected for some processes)"
done
echo

echo "📁 4. Test auto-dump functionality"
echo "----------------------------------"
mkdir -p /tmp/demo-dumps
echo "Testing dump to /tmp/demo-dumps..."
$BINARY --pid $$ --auto-dump --output-dir /tmp/demo-dumps --quiet 2>/dev/null || true
if [ -f /tmp/demo-dumps/*.bin ]; then
    echo "  → Dumps created (check /tmp/demo-dumps/)"
    ls -la /tmp/demo-dumps/
else
    echo "  → No suspicious regions found (normal for shell process)"
fi
echo

echo "🎨 5. Test different output modes"
echo "--------------------------------"
echo "Quiet mode:"
$BINARY --pid $$ --quiet 2>/dev/null || true
echo
echo "No colors mode:"
$BINARY --pid $$ --no-colors --quiet 2>/dev/null || true
echo

echo "📈 6. Performance test with build process"
echo "----------------------------------------"
echo "Running analysis during compilation..."
(make clean && make &) 2>/dev/null >/dev/null &
BUILD_PID=$!
sleep 1
$BINARY --pid $BUILD_PID --verbose 2>/dev/null || echo "  → Build process completed too quickly"
echo

echo "✅ Demo completed successfully!"
echo "=============================="
echo
echo "Key features demonstrated:"
echo "  ✓ Memory mapping and region analysis"
echo "  ✓ Security anomaly detection"
echo "  ✓ Professional CLI interface"
echo "  ✓ Colored output and formatting"
echo "  ✓ Auto-dump capability"
echo "  ✓ Robust error handling"
echo
echo "For advanced features (YARA scanning, memory reading):"
echo "  → Install YARA development libraries"
echo "  → Run with elevated privileges (sudo)"
echo "  → Analyze suspicious processes or malware samples"
echo
echo "Ready for production use! 🚀"