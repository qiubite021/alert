# log_utils.py
#处理日志存储和目录管理。
import os
import datetime
from config import ENCODINGS,BASE_DIR,LISTEN_PORT

def ensure_dir(path):
    if not os.path.exists(path):
        os.makedirs(path)

def get_today_dir():
    today = datetime.datetime.now().strftime("%Y-%m-%d")
    day_dir = os.path.join(BASE_DIR, "raw", today)
    ensure_dir(day_dir)
    return day_dir

def write_log(message: str):
    day_dir = get_today_dir()
    for enc in ENCODINGS:
        log_file = os.path.join(day_dir, f"syslog_{LISTEN_PORT}.{enc}.log")
        try:
            with open(log_file, "a", encoding=enc, errors="ignore") as f:
                f.write(message + "\n")
        except Exception as e:
            print(f"[!] 写文件失败({enc}): {e}")
