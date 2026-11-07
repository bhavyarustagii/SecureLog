import subprocess
import sys
import time
import os

def main():
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"

    for f in ["securelog.db", "security_logs.txt"]:
        if os.path.exists(f):
            try:
                os.remove(f)
                print(f"[*] Cleared old {f}")
            except Exception as e:
                print(f"[WARN] Failed to clear {f}: {e}")

    # Initialize new database
    from db_manager import init_db
    init_db()

    subprocess.Popen(
        [sys.executable, "auto_logger.py"], 
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    time.sleep(2)
    
    script_dir = os.path.dirname(os.path.abspath(__file__))
    api_proc = subprocess.Popen(
        [sys.executable, "api.py"],
        env=env,
        cwd=script_dir,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    frontend_dir = os.path.join(script_dir, "frontend")
    frontend_proc = subprocess.Popen(
        ["npm", "run", "dev", "--", "--host"],
        env=env,
        cwd=frontend_dir,
        shell=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    print("[OK] SecureNet SOC Dashboard running on http://localhost:5173")
    print("Press Ctrl+C to stop all services.")

    try:
        api_proc.wait()
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
