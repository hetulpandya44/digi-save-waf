@echo off
echo ============================================================
echo   Digi Save WAF - Web Application Firewall
echo ============================================================
echo.

cd /d "%~dp0"

echo Installing dependencies...
pip install -r requirements.txt
echo.

echo Starting Digi Save WAF server...
echo Management UI:  http://localhost:8005
echo WAF Proxy:      http://localhost:8085
echo API Docs:       http://localhost:8005/docs
echo Login:          admin / admin123
echo.
echo Press Ctrl+C to stop the server
echo ============================================================

cd backend
python main.py
pause
