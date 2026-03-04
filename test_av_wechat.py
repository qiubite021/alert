# test_av_wechat.py
# 用于测试 安恒 AV 日志 是否能成功发送企业微信告警

from log_parser import parse_log
from wechat_alert import send_wechat_alert
import datetime

# ===== 模拟你刚才发的原始日志 =====
RAW_LOG = """<4>Feb 06 11:34:02 DAS-Gateway;530000200117120668501381;ipv4;3; av: virus_name=W32.Common.B38B7A9B;virus_type=其它;virus_type_en=other;file_name=aseditor_bundle-master-20260127134750.apk;user_name=192.168.126.5;user_id=0;policy_id=12;src_mac=90:f1:b0:fa:25:44;dst_mac=48:8e:ef:b4:df:26;src_ip=192.168.126.5;dst_ip=14.17.91.22;src_port=63377;dst_port=80;app_name=安卓软件下载;app_name_en=android_app_download;protocol=TCP;app_protocol=HTTP;level=warning;ctime=2026-02-06 11:34:02;action=pass"""

def main():
    print("[*] 开始测试安恒 AV 告警发送")

    now_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

    # ===== 构造 log 基础结构（和 main_listener 一致）=====
    log = {
        "device": "AH",
        "log_date": now_time,
        "raw": RAW_LOG,
        "attack_type": "未知",
        "attack_name": "未知",
        "src_ip": "未知",
        "dst_ip": "未知",
        "action": "未知",
        "status": "test"
    }

    # ===== 解析日志 =====
    parsed = parse_log(RAW_LOG, "AH")

    if parsed:
        print("[+] 日志解析成功：")
        for k, v in parsed.items():
            print(f"    {k}: {v}")
        log.update(parsed)
    else:
        print("[!] 日志解析失败（parsed 为空）")

    print("\n[*] 构造完成的 log 对象：")
    for k, v in log.items():
        print(f"  {k}: {v}")

    print("\n[*] 尝试发送企业微信告警...")
    send_wechat_alert(log)

    print("[*] 测试结束")

if __name__ == "__main__":
    main()
