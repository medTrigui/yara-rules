#!/usr/bin/env bash
set -e

find rules -type f \( -name "*.yar" -o -name "*.yara" \) | while read -r rule; do
	echo "Validating $rule"
	yarac "$rule" /tmp/compiled_rule >/dev/null
done

echo "All rules compiled successfully."
