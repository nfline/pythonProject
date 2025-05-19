import requests
import threading

url = "https://yourdomain.com/test"
num_threads = 20

def access_url():
    try:
        response = requests.get(url, timeout=5)
        print(f"Status: {response.status_code}")
    except Exception as e:
        print(f"Error: {e}")

threads = []

for _ in range(num_threads):
    t = threading.Thread(target=access_url)
    t.start()
    threads.append(t)

for t in threads:
    t.join()
