"""Example usage of the session logger."""
from __future__ import annotations

import logging
from random import randint
from time import sleep

from app.session_logger import SessionLoggerError, finish_session, log_action, start_session

log = logging.getLogger("app.main")


def run_task(user: str) -> None:
    session_id = start_session(user)
    try:
        try:
            log_action(session_id, "user_action", payload={"event": "start_button"})
        except Exception:
            log.warning("Failed to log user action", exc_info=True)
        log_action(session_id, "collect_metrics", payload={"packets": 150})
        sleep(randint(1, 2))
        log_action(session_id, "process_data", payload={"status": "in_progress"})
        sleep(randint(1, 2))
        finish_session(
            session_id,
            "OK",
            {
                "packets": 245,
                "duration": "5.2s",
            },
        )
    except Exception as exc:  # noqa: BLE001 - demonstration purposes
        finish_session(session_id, "ERROR", {"error": str(exc)})
        raise


if __name__ == "__main__":
    try:
        run_task("admin")
    except SessionLoggerError as err:
        print(f"Failed to log session: {err}")
