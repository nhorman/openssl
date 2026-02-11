#!/usr/bin/python

import csv
import sys

def check_append_entry(idx, row, array):
    if row[1] == "addr:(nil)":
        # Null addrs can be allocated/freed in any order
        return
    event_addr_id = row[0] + row[1]
    if event_addr_id in array:
        entry = array[event_addr_id]
    else:
        entry = {"index": idx, "row": row, "alloc": 0, "free": 0}
        array[event_addr_id] = entry

    if row[2] == "event:allocate":
        if entry["alloc"] == 1:
            print(f"index {event["index"]} row {event["row"]} double allocated\n")
        entry["alloc"] = 1
        entry["free"] = 0
    elif row[2] == "event:free":
        if entry["alloc"] == 0:
            print(f"index {entry["index"]} row {entry["row"]} freed before alloc\n")
        if entry["free"] == 1:
            print(f"index {entry["index"]} row {entry["row"]} double free\n")
        del array[event_addr_id]
    
def scan_for_leaks(array):
    for key, value in array.items():
        if value["alloc"] == 1 and value["free"] == 0:
            print(f"line {value["index"]} has leaked\n")

def main(argv):
    allocatorarray = {}
    mmaparray = {} 
    slabarray = {} 
    objarray = {} 
    nonslabobjarray = {} 
    idx = 0
    print("Parsing log, scanning for out of order allocs/frees")
    with open(argv[0], newline='') as csvfile:
        csvreader = csv.reader(csvfile, delimiter='|')
        for row in csvreader:
            if row[0] == "type:allocator":
                check_append_entry(idx, row, allocatorarray)
            elif row[0] == "type:mmap":
                check_append_entry(idx, row, mmaparray)
            elif row[0] == "type:slab":
                check_append_entry(idx, row, slabarray)
            elif row[0] == "type:obj":
                check_append_entry(idx, row, objarray)
            elif row[0] == "type:nonslab-obj":
                check_append_entry(idx, row, nonslabobjarray)
            idx = idx + 1
    print(f"Scanning for allocator leaks ({len(allocatorarray)} suspicious events)\n")
    scan_for_leaks(allocatorarray)
    print(f"Scanning for mmap leaks ({len(mmaparray)} suspicious events)\n")
    scan_for_leaks(mmaparray)
    print(f"Scanning for slab leaks ({len(slabarray)} suspicious events)\n")
    scan_for_leaks(slabarray)
    print(f"Scanning for obj leaks ({len(objarray)} suspicious events)\n")
    scan_for_leaks(objarray)
    print(f"Scanning for non slab obj leaks ({len(nonslabobjarray)} suspicious events)\n")
    scan_for_leaks(nonslabobjarray)

if __name__ == "__main__":
    main(sys.argv[1:])
