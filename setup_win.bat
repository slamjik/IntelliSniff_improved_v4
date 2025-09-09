@echo off
python -m venv venv
call venv\\Scripts\\activate
pip install --upgrade pip
if exist requirements.txt (
  pip install -r requirements.txt
)
echo done