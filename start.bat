@echo off
cd /d "%~dp0"
echo ========================================================
echo          SecureLog - Single Button Start
echo ========================================================
echo.
echo Make sure you have started Ganache locally (port 7545)
echo or use Docker for a fully containerized setup.
echo.
echo Note: Network monitor requires Administrator privileges 
echo to capture packets and block IPs via Firewall.
echo.
echo [1] Deploying Smart Contract to Ganache...
python deploy_contract.py
if %errorlevel% neq 0 (
    echo [ERROR] Contract deployment failed. Is Ganache running?
    pause
    exit /b
)
echo.
echo [2] Starting SecureLog (Dashboard + Network Monitor)...
python run_securelog.py
pause
