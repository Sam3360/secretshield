"""
Notification system for secretshield.

Notifications never include the detected secret value, only a generic
warning. Desktop notifications are best-effort and optional: if the
underlying OS mechanism is unavailable, failures are swallowed silently
so the host application is never disrupted.
"""

from __future__ import annotations

import sys

WARNING_MESSAGE = "\u26a0 secretshield: Potential secret detected and redacted."

# Guards against recursive notification loops (e.g. a notification
# triggering logging which triggers detection which triggers another
# notification).
_in_notification = False


def notify_console(stream=None) -> None:
    """
    Print the safe warning message to the given stream (defaults to the
    *original*, unwrapped stderr to avoid re-triggering detection).
    """
    global _in_notification
    if _in_notification:
        return
    _in_notification = True
    try:
        target = stream if stream is not None else sys.__stderr__
        if target is None:
            return
        target.write(WARNING_MESSAGE + "\n")
        target.flush()
    except Exception:
        # Notifications must never crash the host application.
        pass
    finally:
        _in_notification = False


def notify_desktop(title: str = "secretshield", message: str = WARNING_MESSAGE) -> None:
    """
    Best-effort desktop notification. Optional and silent on failure.
    Does not perform any network activity. If no desktop notification
    backend is available, this is a no-op.
    """
    try:
        import subprocess  # local import: only needed for this optional path

        if sys.platform == "darwin":
            script = f'display notification "{message}" with title "{title}"'
            subprocess.run(
                ["osascript", "-e", script],
                check=False,
                capture_output=True,
                timeout=2,
            )
        elif sys.platform.startswith("linux"):
            subprocess.run(
                ["notify-send", title, message],
                check=False,
                capture_output=True,
                timeout=2,
            )
        # Other platforms (e.g. Windows) are intentionally no-ops unless a
        # user wires up their own backend; failing silently is preferred
        # over adding heavier optional dependencies.
    except Exception:
        # Desktop notifications are optional; never let this raise.
        pass
