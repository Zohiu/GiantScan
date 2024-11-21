import time
import threading
import socket
import requests
import os
import datetime
import sqlite3

import ipaddress
from scapy.all import sniff

THIS_PC_IP = "192.168.68.58"
WANTED_PORT = 25565
TOTAL_IPS = 4_294_967_296
TOTAL_SCANNED = 0
DISCOVER_BUFFER = []
READY = False


def progress_counter():
    global READY, TOTAL_SCANNED
    db = sqlite3.connect("filtered_ips.db")
    db.cursor().execute("CREATE TABLE IF NOT EXISTS ips(ip TEXT PRIMARY KEY, scan_time TEXT)")
    db.cursor().execute("CREATE TABLE IF NOT EXISTS data(key TEXT PRIMARY KEY, value INTEGER)")
    db.commit()
    cur = db.cursor()
    cur.execute("SELECT * FROM data WHERE key = (?);", ("total_scanned",))
    fetchall = cur.fetchall()
    if len(fetchall) > 0:
        TOTAL_SCANNED = fetchall[0][1]
        print("Progress has been restored!")
    READY = True

    while True:
        ip = get_ip_address(TOTAL_SCANNED)
        print(f"Current IP: {ip} ({round(TOTAL_SCANNED / TOTAL_IPS, 3) * 100}%)")

        cur = db.cursor()
        time_now = str(datetime.datetime.now()).split(".")[0]

        while len(DISCOVER_BUFFER) > 0:
            ip = DISCOVER_BUFFER.pop(0)
            cur.execute("INSERT OR REPLACE INTO ips (ip, scan_time) VALUES (?, ?)", (ip, time_now,))

        cur.execute("REPLACE INTO data (key, value) VALUES (?, ?)", ("total_scanned", TOTAL_SCANNED,))
        db.commit()

        time.sleep(10)


def cidr_to_int_range(cidr):
    # Parse the CIDR notation
    network = ipaddress.IPv4Network(cidr, strict=False)

    # Convert the network address to an integer (start IP)
    start_ip_int = int(network.network_address)

    # Convert the broadcast address to an integer (end IP)
    end_ip_int = int(network.broadcast_address)

    return start_ip_int, end_ip_int


def get_ip_address(n):
    # Calculate the IP address components
    a = n // (256 * 256 * 256)
    b = (n // (256 * 256)) % 256
    c = (n // 256) % 256
    d = n % 256

    # Format and return the IP address
    return f"{a}.{b}.{c}.{d}"


def packet_handler(packet):
    tcp, ip = packet["TCP"], packet["IP"]
    if tcp.flags != "SA":
        return

    # Only incoming packets
    if THIS_PC_IP not in ip.dst:
        return

    print(f"Service discovered: {packet['IP'].src}")  # Print a summary of the packet
    DISCOVER_BUFFER.append(packet['IP'].src)


if __name__ == '__main__':
    if os.geteuid() != 0:
        exit("use root")

    thread_listen = threading.Thread(target=sniff, kwargs={
        "prn": packet_handler,
        "filter": f"tcp and port {WANTED_PORT}",
        "store": 0
    })
    thread_listen.start()

    thread_progress = threading.Thread(target=progress_counter)
    thread_progress.start()

    # Format is "start_ip: end_ip"
    excluded_ranges = {}

    ipv4_bogons = requests.get("https://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt").text
    for line in ipv4_bogons.split("\n"):
        if line.startswith("#") or not line:
            continue
        r = cidr_to_int_range(line)
        excluded_ranges.update({
            r[0]: r[1]
        })

    while not READY:
        time.sleep(0.1)

    while True:
        if TOTAL_SCANNED in excluded_ranges.keys():
            TOTAL_SCANNED = excluded_ranges[TOTAL_SCANNED]

        try:
            ip = get_ip_address(TOTAL_SCANNED + 1)
            client = socket.socket()
            client.settimeout(0)  # Send requests but ignore any response. Makes scanning FAST
            client.connect((f'{ip}', 25565))
        except BlockingIOError:
            pass

        TOTAL_SCANNED += 1
