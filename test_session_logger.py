from app.session_logger import start_session, log_action, finish_session, list_recent_sessions

def test_session_flow():
    session_id = start_session("admin", details={"task": "pytest test"})
    log_action(session_id, "ping", payload={"msg": "hello"})
    finish_session(session_id, "success", details={"note": "ok"})

    sessions = list_recent_sessions()
    assert any(s["id"] == session_id for s in sessions)
