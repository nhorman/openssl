#!/usr/bin/python

import csv
import sys

def find_matching_free(idx, csvarray):
    objtype = csvarray[idx]["info"][0]
    objaddr = csvarray[idx]["info"][1]

    for entry in csvarray[idx:]:
        if entry["info"][0] == objtype and entry["info"][1] == objaddr and entry["info"][2] == "event:free":
            return
    print(f"{csvarray[idx]} on line {csvarray[idx]["index"]} has no matching free")

def scan_for_leaks(objtype, csvarray):
    indexlist = []
    for index, entry in enumerate(csvarray):
        if entry["info"][0] == objtype and entry["info"][2] == "event:allocate":
            indexlist.append(index)
    print(f"Scanning for leaks in {objtype}, {len(indexlist)} allocations")
    for idx in indexlist:
        find_matching_free(idx, csvarray)
        
def find_double_free_alloc(idx, csvarray):
    freefound = 0
    objaddr = csvarray[idx]["info"][1]
    objtype = csvarray[idx]["info"][0]
    for entry in csvarray[idx+1:]:
        if entry["info"][0] == objtype and entry["info"][1] == objaddr and entry["info"][2] == "event:free":
            freefound = freefound + 1
            if freefound > 1:
                print(f"{csvarray[idx]} on line {csvarray[idx]["index"]} is double freed")
                return
        if entry["info"][0] == objtype and entry["info"][1] == objaddr and entry["info"][2] == "event:allocate":
            if freefound == 1:
                return
            elif freefound == 0:
                print(f"{csvarray[idx]} on line {csvarray[idx]["index"]} is double allocated")
        
def scan_for_double_frees_allocs(objtype, csvarray):
    indexlist = []
    for index, entry in enumerate(csvarray):
        if entry["info"][0] == objtype and entry["info"][2] == "event:allocate":
            indexlist.append(index)
    print(f"Scanning for double frees in {objtype}, {len(indexlist)} allocations")
    for idx in indexlist:
        find_double_free_alloc(idx, csvarray)

def main(argv):
    allocatorarray = []
    mmaparray = []
    slabarray = []
    objarray = []
    nonslabobjarray = []
    idx = 0
    print("Reading in log")
    with open(argv[0], newline='') as csvfile:
        csvreader = csv.reader(csvfile, delimiter='|')
        for row in csvreader:
            entry = { "index" : idx, "info" : row } 
            if row[0] == "type:mmap":
                mmaparray.append(entry)
            if row[0] == "type:allocator":
                allocatorarray.append(entry)
            elif row[0] == "type:slab":
                slabarray.append(entry)
            elif row[0] == "type:obj":
                objarray.append(entry)
            elif row[0] == "type:nonslab-obj":
                nonslabobjarray.append(entry)
            idx = idx + 1
        scan_for_leaks("type:allocator", allocatorarray)
        scan_for_double_frees_allocs("type:allocator", allocatorarray)
        scan_for_leaks("type:mmap", mmaparray)
        scan_for_double_frees_allocs("type:mmap", mmaparray)
        scan_for_leaks("type:slab", slabarray)
        scan_for_double_frees_allocs("type:slab", slabarray)
        scan_for_leaks("type:obj", objarray)
        scan_for_double_frees_allocs("type:obj", objarray)
        scan_for_leaks("type:nonslab-obj", nonslabobjarray)
        scan_for_double_frees_allocs("type:nonslab-obj", nonslabobjarray)
if __name__ == "__main__":
    main(sys.argv[1:])
