# main_listener.py
#启动服务并进行日志监听。
# main_listener.py
import socket
import datetime
from config import LISTEN_IP, LISTEN_PORT, BUFFER_SIZE
from log_utils import write_log
from db_utils import connect_db, save_to_db, check_table_structure
from wechat_alert import send_wechat_alert
from log_parser import parse_log, parse_huawei_atk_log


def start():
    conn = connect_db()
    if not conn:
        print("[!] 数据库连接失败，程序退出")
        return

    required_fields = [
        "log_date", "device_type", "log_content",
        "attack_type", "src_ip", "dst_ip", "action", "status"
    ]
    try:
        check_table_structure(conn, "attack_raw_HUAWEI", required_fields)
        check_table_structure(conn, "attack_raw_AH", required_fields)
        print("[+] 数据库表结构校验通过")
    except Exception as e:
        print(f"[!] 数据库表结构校验失败: {e}")
        return

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((LISTEN_IP, LISTEN_PORT))
    print(f"[+] UDP监听启动 {LISTEN_IP}:{LISTEN_PORT}")

    while True:
        try:
            data, addr = sock.recvfrom(BUFFER_SIZE)
            try:
                msg = data.decode("utf-8")
            except UnicodeDecodeError:
                msg = data.decode("gbk", errors="ignore")

            # 过滤无用日志
            from config import FILTER_KEYWORDS
            if any(keyword in msg for keyword in FILTER_KEYWORDS):
                continue

            now_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

            # 判断设备类型和表名
            if "USG6300E" in msg:
                device = "HUAWEI"
                table = "attack_raw_HUAWEI"
            elif "DAS-Gateway" in msg:
                device = "AH"
                table = "attack_raw_AH"
            else:
                # 不关心的设备日志，跳过
                continue

            # 解析日志
            log = {
                "device": device,
                "log_date": now_time,
                "raw": msg.strip(),
                "attack_name": "未知",
                "attack_type": "未知",
                "src_ip": "未知",
                "dst_ip": "未知",
                "action": "未知",
            }

            if device == "HUAWEI":
                parsed = parse_huawei_atk_log(msg)
                log.update(parsed)

            else:  # AH设备
                # 调用log_parser里的解析函数
                parsed = parse_log(msg,device)
                if parsed:
                     log.update(parsed)
                else:
                     print("[!] 解析为空，仅保存原始日志，不告警")
               # log.update(parsed)

            # 写日志文件
            write_log(f"[{now_time}] [{addr[0]}] {msg.strip()}")

            # 入库并发告警
            save_to_db(conn, table, log)
            send_wechat_alert(log)

        except KeyboardInterrupt:
            print("\n[!] 手动停止程序")
            break
        except Exception as e:
            print(f"[!] 运行时错误: {e}")

if __name__ == "__main__":
    start()

