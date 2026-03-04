# wechat_alert.py
# 负责企业微信告警发送（按设备/日志类型区分模板）

import requests
from config import WECHAT_WEBHOOK
from alert_limit import can_send_alert


# ================= 华为防火墙告警模板 =================
def build_huawei_wechat_message(log: dict) -> str:
    return f"""
### 🚨 华为防火墙威胁告警

**攻击类型**：{log.get("attack_type", "未知")}

**源地址**：{log.get("src_ip", "未知")}:{log.get("src_port", "")}
**目的地址**：{log.get("dst_ip", "未知")}:{log.get("dst_port", "")}

**动作**：{log.get("action", "未知")}
**告警时间**：{log.get("log_date", "未知")}
""".strip()


# ================= 安恒 IPS 告警模板 =================
def build_ah_ips_wechat_message(log: dict) -> str:
    attack_success = log.get("attack_success")
    success_text = {
        "1": "是",
        "0": "否"
    }.get(attack_success, "未知")

    return f"""
### 🚨 安恒防火墙 IPS 告警

**等级**：{log.get("level", "未知")}
**攻击名称**：{log.get("attack_name", "未知")}
**攻击类型**：{log.get("attack_type", "未知")}

**源IP-端口**：{log.get("src_ip", "未知")}
**目的IP-端口**：{log.get("dst_ip", "未知")}

**协议**：{log.get("protocol", "未知")} / {log.get("app_protocol", "未知")}
**策略ID**：{log.get("policy_id", "未知")}
**攻击是否成功**：{success_text}

**动作**：{log.get("action", "未知")}
**告警时间**：{log.get("log_date", "未知")}
""".strip()


# ================= 安恒 AV 防病毒告警模板 =================
def build_ah_av_wechat_message(log: dict) -> str:
    return f"""
### 🦠 安恒防病毒告警

**病毒名称**：{log.get('attack_name', '未知')}
**文件名称**：{log.get('file_name', '未知')}
**用户名称**：{log.get('user_name', '未知')}
**应用名称**：{log.get('app_name', '未知')}

**源IP-端口**：{log.get('src_ip', '未知')}
**目的IP-端口**：{log.get('dst_ip', '未知')}

**等级**：{log.get('level', '未知')}
**动作**：{log.get('action', '未知')}
**告警时间**：{log.get('log_date', '未知')}
""".strip()


# ========== 安恒 扫描 / 洪泛 / 异常攻击 告警模板 ==========
def build_ah_scan_flood_abnormal_wechat_message(log: dict) -> str:
    return f"""
### 🚨 安恒异常流量告警

**攻击名称**：{log.get('attack_name', '未知')}
**攻击类型**：{log.get('attack_type', '未知')}

**用户名称**：{log.get('user_name', '未知')}
**源IP-端口**：{log.get('src_ip', '未知')}
**目的IP-端口**：{log.get('dst_ip', '未知')}

**协议**：{log.get('protocol', '未知')}
**接口名称**：{log.get('in_if_name', '未知')}
**次数**：{log.get('count', '未知')}

**等级**：{log.get('level', '未知')}
**动作**：{log.get('action', '未知')}
**告警时间**：{log.get('log_date', '未知')}
""".strip()


# ================= 对外主函数 =================
def send_wechat_alert(log: dict):

    """
    企业微信告警统一出口
    """
    

    device = log.get("device", "UNKNOWN")
    raw = log.get("raw", "")

    # ===== 告警限流 key 设计（非常关键）=====
    # device + 日志类型 + 攻击名称 + 源IP
def send_wechat_alert(log: dict):

    device = log.get("device", "UNKNOWN")
    raw = log.get("raw", "")

    # ===== 告警限流（直接传 log）=====
    if not can_send_alert(log):
        return

    # ===== 模板选择 =====
    if device == "HUAWEI":
        content = build_huawei_wechat_message(log)

    elif device == "AH":
        if "ips:" in raw:
            content = build_ah_ips_wechat_message(log)
        elif "av:" in raw:
            content = build_ah_av_wechat_message(log)
        elif any(x in raw for x in ("security_scan", "security_flood", "security_abnormal_pkt")):
            content = build_ah_scan_flood_abnormal_wechat_message(log)
        else:
            print("[!] 未识别的安恒日志类型，跳过告警")
            return

    else:
        print("[!] 未识别设备类型，跳过告警")
        return

    payload = {
        "msgtype": "markdown",
        "markdown": {
            "content": content
        }
    }

    try:
        resp = requests.post(WECHAT_WEBHOOK, json=payload, timeout=5)
        if resp.status_code == 200:
            print("[+] 企业微信告警发送成功")
        else:
            print(f"[!] 企业微信告警失败，状态码: {resp.status_code}")
    except Exception as e:
        print(f"[!] 企业微信告警异常: {e}")
