import os
from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET
from datetime import datetime


NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def extract_timestamp(record):
    xml = record.xml()
    root = ET.fromstring(xml)
    time_str = root.find(".//e:TimeCreated", NS).attrib["SystemTime"]
    return datetime.fromisoformat(time_str.replace("Z", "+00:00"))


def get_evtx_range_fast(file_path):
    with Evtx(file_path) as log:
        records = list(log.records())

        if not records:
            return None, None

        first_time = extract_timestamp(records[0])
        last_time = extract_timestamp(records[-1])

        return first_time, last_time


def scan_directory(directory):
    print(f"\nScanning directory: {directory}\n")

    for filename in os.listdir(directory):
        if filename.lower().endswith(".evtx"):
            full_path = os.path.join(directory, filename)

            try:
                first, last = get_evtx_range_fast(full_path)

                if first and last:
                    print(f"{filename}")
                    print(f"  Oldest Event : {first}")
                    print(f"  Newest Event : {last}\n")
                else:
                    print(f"{filename}")
                    print("  No events found\n")

            except Exception as e:
                print(f"{filename}")
                print(f"  Failed to process: {e}\n")


if __name__ == "__main__":
    scan_directory(r"/path/to/your/evtx/files")
