import os, secrets
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
security = HTTPBasic()
def get_current_username(credentials: HTTPBasicCredentials = Depends(security)):
    correct_username = os.getenv('TA_USER', 'admin')
    correct_password = os.getenv('TA_PASS', 'changeme')
    is_correct = secrets.compare_digest(credentials.username, correct_username) and secrets.compare_digest(credentials.password, correct_password)
    if not is_correct:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Unauthorized', headers={'WWW-Authenticate':'Basic'})
    return credentials.username
