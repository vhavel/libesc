#!/bin/bash

BINARY="$1"
if [ -z "$BINARY" ]; then
    echo "Usage: $0 <binary>"
    exit 1
fi

echo "=== Running binary under strace ==="
STRACE_OUT=$(mktemp)
TRACE_FILE=$(mktemp)

# Run under strace, save to file
strace -o "$TRACE_FILE" "$BINARY" 2>&1 | head -1

# Extract syscall names (first word before '(')
cat "$TRACE_FILE" | awk -F'(' '{print $1}' | awk '{print $NF}' | grep -v "^+++" | grep -v "^$" | sort -u > "$STRACE_OUT"

echo "Syscalls executed (from strace):"
cat "$STRACE_OUT"
EXECUTED_COUNT=$(wc -l < "$STRACE_OUT")
echo "Total executed: $EXECUTED_COUNT"
echo

echo "=== Running our tool ==="
DETECTED_OUT=$(mktemp)
./build/cli/esc -s "$BINARY" 2>/dev/null | grep "syscall" | sed 's/.*syscall [0-9]* (\(.*\)).*/\1/' | grep -v "number unknown" | sort -u > "$DETECTED_OUT"

echo "Syscalls detected by our tool:"
cat "$DETECTED_OUT"
DETECTED_COUNT=$(wc -l < "$DETECTED_OUT")
echo "Total detected (with known names): $DETECTED_COUNT"
echo

# Also get total detected including unknown
TOTAL_DETECTED=$(./build/cli/esc -s "$BINARY" 2>/dev/null | grep "0x" | wc -l)
echo "Total detected (including unknown): $TOTAL_DETECTED"
echo

echo "=== Validation ==="
echo "Checking if all executed syscalls were detected..."
MISSING=0
while IFS= read -r syscall; do
    if ! grep -qi "^$syscall$" "$DETECTED_OUT"; then
        echo "MISS: $syscall (executed but not detected)"
        MISSING=$((MISSING + 1))
    fi
done < "$STRACE_OUT"

if [ $MISSING -eq 0 ]; then
    echo "✓ All $EXECUTED_COUNT executed syscalls were detected"
else
    echo "✗ $MISSING executed syscalls were NOT detected"
fi

echo
echo "Extra syscalls detected (not executed in this run):"
comm -13 "$STRACE_OUT" "$DETECTED_OUT" | head -20
EXTRA=$(comm -13 "$STRACE_OUT" "$DETECTED_OUT" | wc -l)
echo "... ($EXTRA extra with known names)"

rm "$STRACE_OUT" "$DETECTED_OUT" "$TRACE_FILE"
