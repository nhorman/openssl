#!/usr/bin/python

import csv
import sys

def find_matching_free(idx, csvarray):
    objtype = csvarray[idx][0]
    objaddr = csvarray[idx][1]

    for row in csvarray[idx:]:
        if row[0] == objtype and row[1] == objaddr and row[2] == "event:free":
            return;
    print(f"{csvarray[idx]} on line {idx} has no matching free")

def scan_for_leaks(objtype, csvarray):
    indexlist = []
    for index, row in enumerate(csvarray):
        if row[0] == objtype and row[2] == "event:allocate":
            indexlist.append(index)
    print(f"Scanning for leaks in {objtype}, {len(indexlist)} instances")
    for idx in indexlist:
        find_matching_free(idx, csvarray)


def main(argv):
    csvarray = []
    with open(argv[0], newline='') as csvfile:
        csvreader = csv.reader(csvfile, delimiter='|')
        for row in csvreader:
            csvarray.append(row)
        scan_for_leaks("type:allocator", csvarray)
        scan_for_leaks("type:slab", csvarray)
        scan_for_leaks("type:obj", csvarray)
        scan_for_leaks("type:nonslab-obj", csvarray)

if __name__ == "__main__":
    main(sys.argv[1:])
