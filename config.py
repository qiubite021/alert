# config.py
#存放所有配置、常量和全局变量。
LISTEN_IP = "0.0.0.0"
LISTEN_PORT = 10515
BASE_DIR = r"C:\ATTACK\fw_log_collect"
BUFFER_SIZE = 65535

DB_HOST = "localhost"
DB_NAME = "ATTACK"
DB_USER = "root"
DB_PASSWORD = "Wabjtam@10011949"
WECHAT_WEBHOOK = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=9bdecd0c-030f-4f73-bd4f-df48fc317e98"
##告警过滤的关键字
FILTER_KEYWORDS = [
    "%%01POLICY/6/", "IPSEC", "%%01IKE", "%%01SHELL", "%%01SECIF","%%01INFO","device_health:", "device_traffic:","IP spoof attack"
]

ENCODINGS = ["utf-8", "gbk"]
#5分钟内发送10次禁止发送告警60分钟
#ALERT_LIMIT = 5 
#ALERT_TIME_FRAME = 10
#ALERT_BLOCK_TIME = 60
