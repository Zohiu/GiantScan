import time
import datetime
from multiprocessing import Pool
from mcstatus import JavaServer
from faker import Faker
import csv


# Function to send a request to a website and return the response
def check_server_status(ip):
    try:
        server = JavaServer.lookup(f"{ip}")
        status = server.status()
        return True, ip, status
    except Exception as e:
        return False, ip, str(e)


def request_loop(fake):
    global total_scans, total_scanned_ips
    while True:
        # Create a multiprocessing pool with the specified number of processes
        pool = Pool(processes=max_concurrent_processes)

        # Start all the processes with a delay between them
        processes = []
        for _ in range(num_processes):
            ip = fake.unique.ipv4()
            process = pool.apply_async(check_server_status, args=(ip,))
            processes.append(process)
            # time.sleep(3 / num_processes)

        # Wait for all processes to complete
        pool.close()
        pool.join()

        total_scans += 1
        total_scanned_ips += len(processes)
        scanned_percent = round(total_scanned_ips / total_ips, 1) * 100
        run_time = time.time() - start_time
        speed = round(total_scanned_ips/run_time, 1)  # IPs / second
        remaining_time = datetime.timedelta(seconds=speed * (total_ips - total_scanned_ips))

        print(f"[{datetime.datetime.now()}] {total_scans}: scan completed | {total_scanned_ips}/{total_ips} IPs ({scanned_percent}%) | {speed} IPs/s | {remaining_time} remaining")

        with open(output_file, 'a', newline='') as file:
            for process in processes:
                found, ip, status = process.get()
                if found:
                    print(f"IP: {ip}, Version: {status.version.name}, Description: {status.description}")

                    writer = csv.writer(file)
                    writer.writerow((ip, status.version.name, status.description, datetime.datetime.now()))

        pool.terminate()


if __name__ == '__main__':
    max_concurrent_processes = 2500
    num_processes = 100_000
    total_ips = 4_294_967_296

    total_scans = 0
    total_scanned_ips = 0

    fake = Faker()
    output_file = "servers.csv"
    start_time = time.time()

    request_loop(fake)