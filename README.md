# GiantScan
Install the requirements (`pip install -r requirements.txt`) and run 
`python3 scan.py` to start scanning the internet for open ports. Default is `25565` for 
Minecraft servers, for which the `check_is_minecraft_server.py` script is included. 
That one is pretty sketchy though so use at your own risk.

Scanning generates a filtered_ips.db SQLite3 database which contains all the
IPs with that port open.

This script requires superuser permissions, because it needs to listen to all incoming
traffic. Read before running.
