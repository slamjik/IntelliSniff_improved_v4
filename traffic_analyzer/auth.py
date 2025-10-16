
import os, secrets, logging
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials

log = logging.getLogger("ta.auth")
security = HTTPBasic()

def _get_creds():
    correct_username = os.getenv('TA_USER', 'admin')
    correct_password = os.getenv('TA_PASS', 'changeme')
    if correct_username == 'admin' and correct_password == 'changeme':
        log.warning("Using default credentials admin/changeme — change TA_USER/TA_PASS in production!")
    return correct_username, correct_password

def get_current_username(credentials: HTTPBasicCredentials = Depends(security)):
    correct_username, correct_password = _get_creds()
    is_correct = secrets.compare_digest(credentials.username, correct_username) and secrets.compare_digest(credentials.password, correct_password)
    if not is_correct:
        # Russian message for unauthorized
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Неавторизован. Неверный логин/пароль.', headers={'WWW-Authenticate':'Basic'})
    return credentials.username
