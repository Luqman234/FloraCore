FLORACORE WEB PHASE 1–20
========================

This package implements the web/backend side of roadmap items 1–20 while preserving
the existing encrypted ESP32 device plane.

After installation:
  cd /home/Luqman/website
  source .venv/bin/activate
  python scripts/floracore_preflight.py
  python scripts/run_regression.py
  gunicorn -w 2 -b 127.0.0.1:5000 app:app

New/expanded web surfaces:
  /plants                 existing page + history/trends/Care Score v2/recommendations
  /notifications          notification inbox + preferences/quiet hours
  /devices/<device_id>    Device page v2/manual control/calibration/diagnostics/reservoirs
  /automations/v2         branching Automation Studio v2 + execution dashboard
  /health/live            process liveness
  /health/ready           database/device-plane readiness

Background notification sweep:
  python scripts/floracore_notification_sweep.py

The installer includes example systemd service/timer files under deploy/ but does NOT
modify /etc/systemd/system automatically. Copy/install them only when you want the
background offline/email sweep to run once per minute.

Firmware-dependent features fail closed. In particular, fertilizer control stays
locked until authenticated firmware capabilities report support AND pump-flow
calibration exists. See FLORAOS_PHASE20_FIRMWARE_HANDOFF.txt.
