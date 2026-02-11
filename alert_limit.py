# alert_limit.py
import datetime
from collections import defaultdict

# 限流配置
ALERT_LIMIT = 5          # 限制次数
ALERT_TIME_FRAME = 10    # 单位：分钟，统计时间窗
ALERT_BLOCK_TIME = 60    # 限流触发后暂停告警的时间，单位秒

# 告警发送时间记录，key=限流key，value=[发送时间列表]
alert_sent_times = defaultdict(list)

# 各日志类型对应的限流Key生成函数
LIMIT_KEY_BUILDERS = {
    "HUAWEI": lambda log: "|".join([
        log.get("device", "UNK"),
        log.get("attack_type", "UNK"),
        log.get("src_ip", "UNK"),
        log.get("dst_ip", "UNK"),
    ]),
    "AH_IPS": lambda log: "|".join([
        log.get("device", "UNK"),
        log.get("attack_type", "UNK"),
        log.get("src_ip", "UNK"),
        log.get("dst_ip", "UNK"),
        log.get("level", "UNK"),
    ]),
    "AV": lambda log: "|".join([
        log.get("device", "UNK"),
        log.get("attack_name", "UNK"),
        log.get("user_name", "UNK"),
        log.get("src_ip", "UNK"),
    ]),
    "SCAN": lambda log: "|".join([
        log.get("device", "UNK"),
        log.get("attack_type", "UNK"),
        log.get("src_ip", "UNK"),
    ]),
    # 你可以继续添加更多类型
}

def build_alert_key(log: dict) -> str:
    """
    根据日志内容和设备，选择对应规则生成限流Key。
    """
    device = log.get("device", "UNK")
    raw = log.get("raw", "").lower()

    if device == "HUAWEI":
        return LIMIT_KEY_BUILDERS["HUAWEI"](log)
    elif device == "AH" and "ips:" in raw:
        return LIMIT_KEY_BUILDERS["AH_IPS"](log)
    elif device == "AH" and "av:" in raw:
        return LIMIT_KEY_BUILDERS["AV"](log)
    elif device == "AH" and (
        "security_scan" in raw or "security_flood" in raw or "security_abnormal_pkt" in raw
    ):
        return LIMIT_KEY_BUILDERS["SCAN"](log)
    else:
        # 默认Key，避免空Key导致误限流
        return "|".join([device, log.get("attack_type", "UNK")])

def _cleanup_old_records(times_list, window_minutes):
    """
    清理超过统计时间窗的告警时间，返回剩余时间列表
    """
    now = datetime.datetime.now()
    return [t for t in times_list if (now - t).total_seconds() < window_minutes * 60]

def _is_blocked(alert_key: str) -> bool:
    """
    判断该限流Key是否处于禁用（暂停发送）状态。
    如果最近一次发送时间距离现在小于ALERT_BLOCK_TIME，则认为被禁用。
    """
    now = datetime.datetime.now()
    times = alert_sent_times.get(alert_key, [])
    if not times:
        return False
    last_time = times[-1]
    if (now - last_time).total_seconds() < ALERT_BLOCK_TIME:
        return True
    return False

def _record_and_check_limit(alert_key: str) -> bool:
    """
    记录当前告警发送时间，判断是否超过ALERT_LIMIT。
    超过则返回False表示限流，不允许发送。
    """
    now = datetime.datetime.now()
    times = alert_sent_times.get(alert_key, [])
    # 清理过期记录
    times = _cleanup_old_records(times, ALERT_TIME_FRAME)
    if len(times) >= ALERT_LIMIT:
        # 超过限制，不记录发送，返回False
        alert_sent_times[alert_key] = times
        return False
    # 允许发送，记录当前时间
    times.append(now)
    alert_sent_times[alert_key] = times
    return True

# 下面是示例调用，可以在 send_wechat_alert 中用

def can_send_alert(log: dict) -> bool:
    """
    判断是否允许发送告警，结合限流key生成和限制检测
    """
    key = build_alert_key(log)
    if _is_blocked(key):
        print(f"[!] 告警限流中，禁止发送: {key}")
        return False
    if not _record_and_check_limit(key):
        print(f"[!] 告警超过限制，暂停发送: {key}")
        return False
    return True
