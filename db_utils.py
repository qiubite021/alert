# db_utils.py
#处理数据库连接、表结构校验和日志存储。
import pymysql
from config import DB_HOST, DB_USER, DB_PASSWORD, DB_NAME

def connect_db():
    try:
        conn = pymysql.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME,
            charset="utf8mb4",
            cursorclass=pymysql.cursors.DictCursor
        )
        print("[+] 数据库连接成功")
        return conn
    except Exception as e:
        print(f"[!] 数据库连接失败: {e}")
        return None

def check_table_structure(conn, table_name, required_fields):
    with conn.cursor() as cur:
        cur.execute(f"SHOW COLUMNS FROM {table_name}")
        columns = cur.fetchall()
        existing_fields = set(col['Field'] for col in columns)

    missing_fields = [f for f in required_fields if f not in existing_fields]

    if missing_fields:
        raise Exception(f"表 `{table_name}` 缺少字段: {missing_fields}")

def save_to_db(conn, table, log):
    sql = """
    INSERT INTO {table}
    (log_date, device_type, log_content, attack_type, src_ip, dst_ip, action, status)
    VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
    """.format(table=table)

    with conn.cursor() as cur:
        cur.execute(sql, (
            log["log_date"], log["device"], log["raw"], log["attack_type"],
            log["src_ip"], log["dst_ip"], log["action"], "未处理"
        ))
    conn.commit()
    print(f"[+] 日志入库成功: {log['raw'][:50]}...")
