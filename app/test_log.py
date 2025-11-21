from app.session_logger import start_session, log_action, finish_session

sid = start_session("test_user", details={"a": 1})
log_action(sid, "ping", payload={"msg": "hello"})
finish_session(sid, "success", {"done": True})

print("Записано!")
