import os
from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET
from datetime import datetime

def get_evtx_range(file_path, sample_size=10):
    """
    Get the oldest and newest event timestamps from an EVTX file.
    
    Args:
        file_path: Path to the EVTX file
        sample_size: Number of records to check from start and end
    """
    oldest = None
    newest = None
    
    with Evtx(file_path) as log:
        records = list(log.records())
        total_records = len(records)
        
        if total_records == 0:
            return None, None
        
        # Determine which records to check
        if total_records <= sample_size * 2:
            # If file is small, check all records
            records_to_check = records
        else:
            # Check first N and last N records
            records_to_check = records[:sample_size] + records[-sample_size:]
        
        for record in records_to_check:
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

def scan_directory(directory, sample_size=10):
    """
    Scan a directory for EVTX files and report their time ranges.
    
    Args:
        directory: Path to directory containing EVTX files
        sample_size: Number of records to sample from each end of the file
    """
    evtx_files = [f for f in os.listdir(directory) if f.lower().endswith(".evtx")]
    
    print(f"Found {len(evtx_files)} EVTX file(s)\n")
    
    for filename in evtx_files:
        full_path = os.path.join(directory, filename)
        print(f"Processing {filename}...")
        try:
            first, last = get_evtx_range(full_path, sample_size)
            if first and last:
                print(f"  Oldest Event: {first}")
                print(f"  Newest Event: {last}")
                duration = last - first
                print(f"  Time Span: {duration}")
            else:
                print(f"  No events found")
            print()
        except Exception as e:
            print(f"  Failed to process {filename}: {e}")
            print()

if __name__ == "__main__":
    scan_directory(r"C:\Path\To\Your\EvtxFiles", sample_size=10)
