import os
from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET
from datetime import datetime

def get_evtx_range(file_path):
    oldest = None
    newest = None

    with Evtx(file_path) as log:
        for record in log.records():
            try:
                xml = record.xml()
                root = ET.fromstring(xml)
                time_str = root.find(".//{http://schemas.microsoft.com/win/2004/08/events/event}TimeCreated").attrib["SystemTime"]
                event_time = datetime.fromisoformat(time_str.replace("Z", "+00:00"))

                if not oldest or event_time < oldest:
                    oldest = event_time
                if not newest or event_time > newest:
                    newest = event_time

            except Exception:
                continue

    return oldest, newest


def scan_directory(directory):
    for filename in os.listdir(directory):
        if filename.lower().endswith(".evtx"):
            full_path = os.path.join(directory, filename)
            print(f"Processing {filename}...")
            try:
                first, last = get_evtx_range(full_path)
                print(f"  Oldest Event: {first}")
                print(f"  Newest Event: {last}")
                print()
            except Exception as e:
                print(f"  Failed to process {filename}: {e}")
                print()


if __name__ == "__main__":
    scan_directory(r"C:\Path\To\Your\EvtxFiles")
