import pyshark  # Requires "TShark" app. "sudo dpkg-reconfigure wireshark-common" & "sudo chmod 777 /usr/bin/dumpcap"
# Wireshark filter:
# tcp && tcp.port == 25565 && ip.dst == 192.168.68.58 && tcp.flags.syn == 1 && !icmp
# Remember insert your own local IP in "ip.dst == [IP]"

import socket
import time
import datetime
import threading
import sys
import sqlite3


TOTAL_IPS = 4_294_967_296
TOTAL_SCANNED = 0
PER_SECOND = 5_000
DISCOVER_BUFFER = []
RUNNING = False


class Clock:
    def __init__(self, fps):
        self.last_time = time.perf_counter()
        self.delay = 1 / fps

    def tick(self):
        _t = time.time()
        _delta = (_t - self.last_time)

        _delay = (self.delay - _delta)
        time.sleep(max(0, _delay))

        self.last_time = time.time()
        return max(self.delay, _delta)


def get_ip_address(n):
    # Calculate the IP address components
    a = n // (256 * 256 * 256)
    b = (n // (256 * 256)) % 256
    c = (n // 256) % 256
    d = n % 256

    # Format and return the IP address
    return f"{a}.{b}.{c}.{d}"


def request_sender():
    global PER_SECOND, TOTAL_SCANNED
    clock = Clock(fps=PER_SECOND)

    while True:
        if not RUNNING:
            return

        if TOTAL_SCANNED == TOTAL_IPS:
            sys.exit("All IPs have been scanned.")

        try:
            client = socket.socket()
            client.settimeout(0)  # Send requests but ignore any response. Makes scanning FAST
            client.connect((f'{get_ip_address(TOTAL_SCANNED + 1)}', 25565))
        except BlockingIOError:
            pass

        TOTAL_SCANNED += 1
        PER_SECOND = 1 / clock.tick()
        # print(fake.)


def sniff_network():
    capture = pyshark.LiveCapture(interface='enp3s0', bpf_filter="tcp port 25565 and ip dst 192.168.68.58 and tcp[tcpflags] == (tcp-syn + tcp-ack)")

    for packet in capture.sniff_continuously():
        try:
            DISCOVER_BUFFER.append(packet.ip.src)
        except AttributeError as e:
            pass


def manager():
    global TOTAL_SCANNED
    total_discovered = 0
    exit_next = False

    db = sqlite3.connect("filtered_ips.db")
    db.cursor().execute("CREATE TABLE IF NOT EXISTS ips(ip TEXT, scan_time TEXT)")
    db.cursor().execute("CREATE TABLE IF NOT EXISTS data(key TEXT PRIMARY KEY, value INTEGER)")
    cur = db.cursor()
    cur.execute("SELECT * FROM data WHERE key = (?);", ("total_scanned",))
    fetchall = cur.fetchall()
    TOTAL_SCANNED = 0
    if len(fetchall) > 0:
        TOTAL_SCANNED = fetchall[0][1]
        print("Progress has been restored!")

    db.commit()

    while True:
        time.sleep(5)

        cur = db.cursor()
        time_now = str(datetime.datetime.now()).split(".")[0]

        while len(DISCOVER_BUFFER) > 0:
            total_discovered += 1
            ip = DISCOVER_BUFFER.pop(0)
            cur.execute("INSERT OR REPLACE INTO ips (ip, scan_time) VALUES (?, ?)", (ip, time_now,))

        cur.execute("REPLACE INTO data (key, value) VALUES (?, ?)", ("total_scanned", TOTAL_SCANNED,))
        cur.execute("REPLACE INTO data (key, value) VALUES (?, ?)", ("total_discovered", total_discovered,))

        db.commit()

        if exit_next:
            return

        if not RUNNING:
            exit_next = True
        else:
            time_remaining = str(datetime.timedelta(seconds=TOTAL_IPS / max(0.1, round(PER_SECOND)))).split(".")[0]
            print(f"{round(PER_SECOND)}/s | {TOTAL_SCANNED} scanned ({round(TOTAL_SCANNED/TOTAL_IPS*100, 4)}%) | {total_discovered} discovered | {time_remaining} remaining")


if __name__ == "__main__":
    RUNNING = True

    sniff_network_thread = threading.Thread(target=sniff_network)
    sniff_network_thread.start()

    time.sleep(1)  # Wait before sending requests to give pyshark some time.

    request_sender_thread = threading.Thread(target=request_sender)
    request_sender_thread.start()

    manager_thread = threading.Thread(target=manager)
    manager_thread.start()

    exit_requested = False  # Flag to indicate if an exit is requested

    try:
        manager_thread.join()

    except KeyboardInterrupt:
        print("Exiting safely! Please wait a bit!")
        RUNNING = False
        while threading.active_count() > 1:
            pass
        sys.exit("Bye!")

