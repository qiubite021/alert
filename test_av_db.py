# test_ah_av_to_db.py
# 用于测试：安恒 AV 日志 → 解析 → 入库

import datetime
from db_utils import connect_db, save_to_db
from log_parser import parse_log

# =========================
# 1. 原始 AV 日志（你给的那条）
# =========================
RAW_MSG = (
    "[2026-02-06 11:34] [172.18.24.4] <4>Feb 06 11:34:02 DAS-Gateway;"
    "530000200117120668501381;ipv4;3; av: "
    "virus_name=W32.Common.B38B7A9B;"
    "virus_type=其它;"
    "virus_type_en=other;"
    "file_name=aseditor_bundle-master-20260127134750.apk;"
    "user_name=192.168.126.5;"
    "user_id=0;"
    "policy_id=12;"
    "src_mac=90:f1:b0:fa:25:44;"
    "dst_mac=48:8e:ef:b4:df:26;"
    "src_ip=192.168.126.5;"
    "dst_ip=14.17.91.22;"
    "src_port=63377;"
    "dst_port=80;"
    "app_name=安卓软件下载;"
    "app_name_en=android_app_download;"
    "protocol=TCP;"
    "app_protocol=HTTP;"
    "level=warning;"
    "ctime=2026-02-06 11:34:02;"
    "action=pass"
)

TABLE_NAME = "attack_raw_AH"

print("[*] 开始测试 安恒 AV 日志 → 解析 → 入库")

# =========================
# 2. 构造基础 log
# =========================
log = {
    "device": "AH",
    "log_date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
    "raw": RAW_MSG,
}

# =========================
# 3. 走真实解析逻辑
# =========================
parsed = parse_log(RAW_MSG, "AH")

if not parsed:
    print("[!] 日志解析失败（parsed 为空）")
else:
    print("[+] 日志解析成功，解析结果：")
    for k, v in parsed.items():
        print(f"    {k}: {v}")

log.update(parsed)

# =========================
# 4. 兜底（防止解析字段缺失）
# =========================
log.setdefault("attack_type", "病毒防护日志")
log.setdefault("src_ip", "未知")
log.setdefault("dst_ip", "未知")
log.setdefault("action", "未知")

# =========================
# 5. 入库
# =========================
conn = connect_db()
if not conn:
    print("[!] 数据库连接失败，测试终止")
    exit(1)

try:
    save_to_db(conn, TABLE_NAME, log)
    print("[+] AV 日志入库测试成功 ✅")
except Exception as e:
    print("[!] AV 日志入库失败 ❌")
    print("错误信息：", e)
finally:
    conn.close()
