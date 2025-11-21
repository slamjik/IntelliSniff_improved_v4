"""In-memory validation of IntelliSniff logging components using SQLite."""
from __future__ import annotations

import os
import pathlib
import time
from datetime import datetime, timedelta, timezone
from typing import Dict

# Configure temporary SQLite database before importing DB-dependent modules
DB_FILE = pathlib.Path("./logging_validation.db")
if DB_FILE.exists():
    DB_FILE.unlink()

os.environ["DATABASE_URL"] = f"sqlite:///{DB_FILE}"  # shared file across sessions

from app import models  # noqa: E402
from app.db import SessionLocal, engine  # noqa: E402
from app.session_logger import finish_session, log_action, start_session  # noqa: E402
from traffic_analyzer.flow_logger import FlowLogger  # noqa: E402


def reset_schema() -> None:
    models.Base.metadata.drop_all(bind=engine)
    models.Base.metadata.create_all(bind=engine)


def validate_sessions() -> None:
    session_id = start_session("validator", details={"case": "session"})
    log_action(session_id, "step", payload={"ok": True})
    finish_session(session_id, "success", details={"ended": True})

    with SessionLocal() as db:
        session = db.get(models.SessionLog, session_id)
        assert session is not None, "Session was not persisted"
        assert session.finished_at.tzinfo is not None, "Session timestamp must be tz-aware"
        assert session.actions, "Session actions must be recorded"


def validate_flow_logging() -> None:
    logger = FlowLogger(max_age_hours=0.0001, max_rows=2)

    base_flow: Dict[str, object] = {
        "iface": r"\\Device\\NPF_{E1DC4433-903A-4F7A-B446-A8253F5CFA1B}",
        "src": "10.0.0.1",
        "dst": "2001:db8::1",
        "sport": 12345,
        "dport": 80,
        "proto": "TCP",
        "packets": 10,
        "bytes": 2048,
        "label": "test",
        "label_name": "integration",
        "score": 0.42,
        "summary": {"note": "validation"},
    }

    first_ts = int((datetime.now(timezone.utc) - timedelta(seconds=1)).timestamp() * 1000)
    flow_id_1 = logger.save_flow({**base_flow, "ts": first_ts})
    assert flow_id_1, "First flow insert failed"

    time.sleep(0.5)
    flow_id_2 = logger.save_flow({**base_flow, "ts": int(time.time() * 1000), "label": "recent"})
    assert flow_id_2, "Second flow insert failed"

    flow_id_3 = logger.save_flow({**base_flow, "ts": int(time.time() * 1000), "label": "newest"})
    assert flow_id_3, "Third flow insert failed"

    with SessionLocal() as db:
        flows = db.query(models.Flow).order_by(models.Flow.id).all()
        assert len(flows) == 2, "Retention should keep only the newest two flows"
        assert all(f.ts.tzinfo is not None for f in flows), "Flow timestamps must be tz-aware"
        assert any(f.label == "newest" for f in flows), "Newest flow should be retained"
        assert all(len(f.iface) <= 128 for f in flows), "Interface length must be accepted"


if __name__ == "__main__":
    reset_schema()
    validate_sessions()
    validate_flow_logging()
    print("Validation completed successfully.")
