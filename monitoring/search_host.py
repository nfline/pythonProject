import socket
import threading
import queue
import time
from datetime import datetime

def scan_host(host, port, timeout=1):
    """
    Scan a single host:port combination
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        if result == 0:
            try:
                service = socket.getservbyport(port)
            except:
                service = "unknown"
            return f"{host}:{port} is open ({service})"
        sock.close()
    except:
        pass
    return None

def worker(q, results, timeout):
    """
    Worker thread to process the queue
    """
    while True:
        try:
            host, port = q.get_nowait()
            result = scan_host(host, port, timeout)
            if result:
                results.append(result)
        except queue.Empty:
            break
        finally:
            q.task_done()

def scan_network(network, ports, threads=100, timeout=1):
    """
    Scan a network range for open ports
    """
    work_queue = queue.Queue()
    results = []

    # Fill the queue with work items
    for host in network:
        for port in ports:
            work_queue.put((host, port))

    # Create and start threads
    thread_list = []
    for _ in range(threads):
        t = threading.Thread(target=worker, args=(work_queue, results, timeout))
        t.start()
        thread_list.append(t)

    # Wait for all threads to complete
    for t in thread_list:
        t.join()

    return results

def generate_ip_range(start_ip, end_ip):
    """
    Generate a list of IPs between start_ip and end_ip
    """
    start = list(map(int, start_ip.split(".")))
    end = list(map(int, end_ip.split(".")))
    temp = start
    ip_range = []
    
    ip_range.append(start_ip)
    while temp != end:
        start[3] += 1
        for i in (3, 2, 1):
            if temp[i] == 256:
                temp[i] = 0
                temp[i-1] += 1
        ip_range.append(".".join(map(str, temp)))
    
    return ip_range

def main():
    """
    Main function to run the host scanner
    """
    # Configuration
    start_ip = "192.168.1.1"
    end_ip = "192.168.1.255"
    ports = [21, 22, 23, 25, 53, 80, 443, 3389, 8080]  # Common ports to scan
    
    print(f"Starting scan at {datetime.now()}")
    print(f"Scanning IP range: {start_ip} - {end_ip}")
    print(f"Ports to scan: {ports}")
    
    # Generate IP range
    ip_range = generate_ip_range(start_ip, end_ip)
    
    # Start scanning
    start_time = time.time()
    results = scan_network(ip_range, ports)
    
    # Print results
    print("\nScan Results:")
    for result in sorted(results):
        print(result)
    
    print(f"\nScan completed in {time.time() - start_time:.2f} seconds")
    print(f"Found {len(results)} open ports")

if __name__ == "__main__":
    main()