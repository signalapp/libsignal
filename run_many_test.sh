#!/bin/bash
passes=0
fails=0

for i in {1..20}; do
  if RUST_BACKTRACE=1 RUST_LOG=info cargo test test_pvrf_mitm -- --show-output > /dev/null 2>&1; then
    ((passes++))
    echo "PASS $i"
  else
    ((fails++))
    echo "FAIL $i"
  fi
done

echo "Done."
echo "Passes: $passes"
echo "Fails: $fails"