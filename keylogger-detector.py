import psutil
import ctypes
import time
import logging

# Configure logging
logging.basicConfig(filename="../logs/sample_log.txt", level=logging.INFO, format='%(asctime)s - %(message)s')
logging.info("=== Keylogger Detection Started ===")

# Suspicious process keywords
SUSPICIOUS_KEYWORDS = ['keylogger', 'logger', 'keyboard', 'hook', 'sniffer']

def is_suspicious(proc):
    try:
        name = proc.name().lower()
        cmdline = ' '.join(proc.cmdline()).lower()
        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in name or keyword in cmdline:
                return True
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        pass
    return False

def scan_processes():
    suspicious_found = []
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        if is_suspicious(proc):
            logging.info(f"[!] Suspicious process: {proc.info}")
            suspicious_found.append(proc.info)
    return suspicious_found

if __name__ == "__main__":
    print("Scanning for suspicious keylogging processes...")
    found = scan_processes()
    if found:
        print(f"[!] {len(found)} suspicious processes found. Check logs/sample_log.txt")
    else:
        print("[+] No suspicious keylogging activity detected.")
    logging.info("=== Scan Completed ===")
