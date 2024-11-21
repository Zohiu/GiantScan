import threading
import time
import datetime
from concurrent.futures import ThreadPoolExecutor
from multiprocessing import Pool
from mcstatus import JavaServer
import sqlite3

MAX_THREADS = 5
FORCE_SCAN_ALL = True
PRINT_ONLY_WHEN_PLAYERS_ONLINE = True

target_db = sqlite3.connect("target_ips.db")

DATA = []

# Function to send a request to a website and return the response
def check_server_status(ip):
    try:
        server = JavaServer.lookup(f"{ip}")
        status = server.status()
        if (not PRINT_ONLY_WHEN_PLAYERS_ONLINE) or status.players.online > 0:
            print(f"Discovered {status.players.online} players at {ip} on {status.version.name}: {status.motd.parsed[0]}")

        DATA.append((ip, status.version.name, str(status.motd.parsed[0]),))
        return True, status
    except Exception as e:
        return False, str(e)


def request_loop():
    filtered_db = sqlite3.connect("filtered_ips.db")

    target_db.cursor().execute("CREATE TABLE IF NOT EXISTS servers(ip TEXT PRIMARY KEY, version TEXT, status TEXT)")
    target_db.commit()

    threads = []

    # Get all possible IPs
    for row in filtered_db.cursor().execute("SELECT * FROM ips"):
        ip = row[0]
        # Skip validated ones
        if FORCE_SCAN_ALL and len(target_db.execute(f"SELECT * FROM servers WHERE ip='{ip}'").fetchall()) > 0:
            continue

        threads.append(threading.Thread(target=check_server_status, args=(ip,)))

    filtered_db.close()

    for thread in threads:
        thread.start()

    threads[-1].join()  # Join the last thread
    time.sleep(10)
    for server in DATA:
        cur = target_db.cursor()
        cur.execute("INSERT OR REPLACE INTO servers (ip, version, status) VALUES (?, ?, ?)",
                    (server[0], server[1], server[2],))

    target_db.commit()


if __name__ == '__main__':
    request_loop()