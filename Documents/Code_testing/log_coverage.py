import os
from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET
from datetime import datetime

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

def extract_timestamp(record):
    try:
        xml = record.xml()
        root = ET.fromstring(xml)
        time_str = root.find(".//e:TimeCreated", NS).attrib["SystemTime"]
        return datetime.fromisoformat(time_str.replace("Z", "+00:00"))
    except Exception:
        return None


def get_evtx_range(file_path):
    oldest = None
    newest = None

    with Evtx(file_path) as log:
        for record in log.records():
            ts = extract_timestamp(record)
            if not ts:
                continue

            if oldest is None or ts < oldest:
                oldest = ts

            if newest is None or ts > newest:
                newest = ts

    return oldest, newest


def scan_directory(directory):
    print(f"\nScanning: {directory}\n")

    for filename in os.listdir(directory):
        if filename.lower().endswith(".evtx"):
            path = os.path.join(directory, filename)

            try:
                oldest, newest = get_evtx_range(path)

                print(f"{filename}")
                print(f"  Oldest Event : {oldest}")
                print(f"  Newest Event : {newest}\n")

            except Exception as e:
                print(f"{filename}")
                print(f"  Error: {e}\n")


if __name__ == "__main__":
    scan_directory("/path/to/evtx")
