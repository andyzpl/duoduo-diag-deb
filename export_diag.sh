#!/bin/bash
# Run on jailbroken device: export DuoduoDiag log + process/signature/network snapshot
LOG=/var/mobile/Documents/duoduo_diag.log
OUT=/var/mobile/Documents/duoduo_diag_export.txt
{
  echo "===== EXPORT TIME: $(date) ====="
  echo "===== DEVICE ====="
  uname -a 2>/dev/null
  sw_vers 2>/dev/null
  echo "===== DUODUO PROCESS ====="
  ps aux | grep -i AMStation | grep -v grep
  echo "===== LOG LINES ====="
  wc -l "$LOG" 2>/dev/null
  echo "===== LOG CONTENT ====="
  cat "$LOG" 2>/dev/null || echo "(log missing)"
  echo "===== END ====="
} > "$OUT" 2>&1
echo "Exported to: $OUT"
cat "$OUT"
