# log_parser.py
import re
import datetime


def parse_huawei_atk_log(msg: str) -> dict:
    log = {
        "attack_type": "未知",
        "attack_name": "未知",
        "src_ip": "未知",
        "src_port": "",
        "dst_ip": "未知",
        "dst_port": "",
        "action": "未知",
    }

    # ================== 攻击类型 ==================
    m_type = (
        re.search(r'攻击类型="([^"]+)"', msg) or
        re.search(r'AttackType="([^"]+)"', msg, re.IGNORECASE)
    )

    # ================== 攻击地址 ==================
    m_addr = (
        re.search(r'攻击地址="([^"]+)"', msg) or
        re.search(r'ip="([^"]+)"', msg, re.IGNORECASE)
    )

    # ================== 动作 ==================
    m_action = (
        re.search(r'动作="([^"]+)"', msg) or
        re.search(r'Action="([^"]+)"', msg, re.IGNORECASE)
    )

    # ================== 赋值 ==================
    if m_type:
        log["attack_type"] = m_type.group(1)
        log["attack_name"] = m_type.group(1)

    if m_addr:
        first_addr = m_addr.group(1).split(";")[0].strip()
        m_pair = re.match(
            r'(?P<src_ip>[^:]+):(?P<src_port>\d+)->(?P<dst_ip>[^:]+):(?P<dst_port>\d+)',
            first_addr
        )
        if m_pair:
            log.update(m_pair.groupdict())

    if m_action:
        log["action"] = m_action.group(1)

    return log



def parse_ah_ips_log(msg: str) -> dict:
    def get(field):
        m = re.search(rf'{field}=([^;]+)', msg)
        return m.group(1) if m else "未知"

    return {
        "attack_name": get("event_name"),
        "attack_type": get("event_type"),
        "src_ip": f"{get('src_ip')}:{get('src_port')}",
        "dst_ip": f"{get('dst_ip')}:{get('dst_port')}",
        "action": get("action"),
        "level": get("level"),
    }


def parse_av_log(msg: str) -> dict:
    def get(field):
        m = re.search(rf'{field}=([^;]+)', msg)
        return m.group(1) if m else "未知"

    return {
        "attack_name": get("virus_name"),
        "attack_type": "病毒防护日志",
        "file_name": get("file_name"),
        "user_name": get("user_name"),
        "app_name": get("app_name"),
        "src_ip": f"{get('src_ip')}:{get('src_port')}",
        "dst_ip": f"{get('dst_ip')}:{get('dst_port')}",
        "protocol": get("protocol"),
        "app_protocol": get("app_protocol"),
        "level": get("level"),
        "action": get("action"),
    }



def parse_ah_scan_flood_abnormal_log(msg: str) -> dict:
    if "security_" not in msg:
        return {}
    return {
        "attack_name": "异常流量",
        "attack_type": "扫描/洪泛",
        "action": "未知",
    }


def parse_log(msg: str, device: str) -> dict:
    if device == "HUAWEI":
        return parse_huawei_atk_log(msg)

    if device == "AH":
        if "ips:" in msg:
            return parse_ah_ips_log(msg)
        msg_for_av = msg.replace("\n", "").replace("\r", "").lower()
        if "av:" in msg_for_av:
            print("[DEBUG] 命中 AV 日志")
            return parse_av_log(msg)
        if any(x in msg for x in ("security_scan", "security_flood", "security_abnormal_pkt")):
            return parse_ah_scan_flood_abnormal_log(msg)

    return {}
