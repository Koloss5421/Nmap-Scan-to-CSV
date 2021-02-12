#!/usr/bin/env python
#
# Modified to show all port information from the scan (filtered, open, closed) and
# removed stuff I didn't need. THANKS!
#
# Credit to:
__author__ = 'Jake Miller (@LaconicWolf)'
__date__ = '20171220'
__version__ = '0.02'
__description__ = """Parses the XML output from an nmap scan. The user
                  can specify whether the data should be printed,
                  displayed as a list of IP addresses, or output to
                  a csv file. Will append to a csv if the filename
                  already exists.
                  """

import xml.etree.ElementTree as etree
import os
import csv
import argparse
from collections import Counter
from time import sleep

def get_host_data(root):
    """Traverses the xml tree and build lists of scan information
    and returns a list of lists.
    """
    host_data = []
    hosts = root.findall('host')
    for host in hosts:
        addr_info = []


        # Get IP address and host info. If no hostname, then ''
        ip_address = host.findall('address')[0].attrib['addr']
        host_name_element = host.findall('hostnames')
        try:
            host_name = host_name_element[0].findall('hostname')[0].attrib['name']
        except IndexError:
            host_name = ''

        # If we only want the IP addresses from the scan, stop here
        if args.ip_addresses:
            addr_info.extend((ip_address, host_name))
            host_data.append(addr_info)
            continue

        # Get information on ports and services
        try:
            port_element = host.findall('ports')
            ports = port_element[0].findall('port')
            for port in ports:
                port_data = []

                proto = port.attrib['protocol']
                port_id = port.attrib['portid']
                service = port.findall('service')[0].attrib['name']
                try:
                    state = port.findall('state')[0].attrib['state']
                except (IndexError, KeyError):
                    state = ''
                try:
                    script_id = port.findall('script')[0].attrib['id']
                except (IndexError, KeyError):
                    script_id = ''
                try:
                    script_output = port.findall('script')[0].attrib['output']
                except (IndexError, KeyError):
                    script_output = ''

                # Create a list of the port data
                port_data.extend((ip_address, host_name,
                                  proto, port_id, state, service, script_id, script_output))

                # Add the port data to the host data
                host_data.append(port_data)

        # If no port information, just create a list of host information
        except IndexError:
            addr_info.extend((ip_address, host_name))
            host_data.append(addr_info)
    return host_data

def parse_xml(filename):
    """Given an XML filename, reads and parses the XML file and passes the
    the root node of type xml.etree.ElementTree.Element to the get_host_data
    function, which will futher parse the data and return a list of lists
    containing the scan data for a host or hosts."""
    try:
        tree = etree.parse(filename)
    except Exception as error:
        print("[-] A an error occurred. The XML may not be well formed. "
              "Please review the error and try again: {}".format(error))
        exit()
    root = tree.getroot()
    scan_data = get_host_data(root)
    return scan_data

def parse_to_csv(data):
    """Given a list of data, adds the items to (or creates) a CSV file."""
    if not os.path.isfile(csv_name):
        csv_file = open(csv_name, 'w', newline='')
        csv_writer = csv.writer(csv_file)
        top_row = [
            'IP', 'Host', 'Proto', 'Port', 'State',
            'Service',
            'NSE Script ID', 'NSE Script Output'
        ]
        csv_writer.writerow(top_row)
        print('\n[+] The file {} does not exist. New file created!\n'.format(
                csv_name))
    else:
        try:
            csv_file = open(csv_name, 'a', newline='')
        except PermissionError as e:
            print("\n[-] Permission denied to open the file {}. "
                  "Check if the file is open and try again.\n".format(csv_name))
            print("Print data to the terminal:\n")
            if args.debug:
                print(e)
            for item in data:
                print(' '.join(item))
            exit()
        csv_writer = csv.writer(csv_file)
        print('\n[+] {} exists. Appending to file!\n'.format(csv_name))
    for item in data:
        csv_writer.writerow(item)
    csv_file.close()

def list_ip_addresses(data):
    """Parses the input data to return only the IP address information"""
    ip_list = [item[0] for item in data]
    sorted_set = sorted(set(ip_list))
    addr_list = [ip for ip in sorted_set]
    return addr_list

def print_data(data):
    """Prints the data to the terminal."""
    for item in data:
        print(' '.join(item))

def main():
    """Main function of the script."""
    for filename in args.filename:

        # Checks the file path
        if not os.path.exists(filename):
            parser.print_help()
            print("\n[-] The file {} cannot be found or you do not have "
                  "permission to open the file.".format(filename))
            continue

        if not args.skip_entity_check:
            # Read the file and check for entities
            with open(filename) as fh:
                contents = fh.read()
                if '<!entity' in contents.lower():
                    print("[-] Error! This program does not permit XML "
                          "entities. Ignoring {}".format(filename))
                    print("[*] Use -s (--skip_entity_check) to ignore this "
                          "check for XML entities.")
                    continue
        data = parse_xml(filename)
        if not data:
            print("[*] No data found.")
            exit()
        if args.csv:
            parse_to_csv(data)
        if args.ip_addresses:
            addrs = list_ip_addresses(data)
            for addr in addrs:
                print(addr)
        if args.print_all:
            print_data(data)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--debug",
                        help="Display error information",
                        action="store_true")
    parser.add_argument("-s", "--skip_entity_check",
                        help="Skip the check for XML entities",
                        action="store_true")
    parser.add_argument("-p", "--print_all",
                        help="Display scan information to the screen",
                        action="store_true")
    parser.add_argument("-ip", "--ip_addresses",
                        help="Display a list of ip addresses",
                        action="store_true")
    parser.add_argument("-csv", "--csv",
                        nargs='?', const='scan.csv',
                        help="Specify the name of a csv file to write to. "
                             "If the file already exists it will be appended")
    parser.add_argument("-f", "--filename",
                        nargs='*',
                        help="Specify a file containing the output of an nmap "
                             "scan in xml format.")
    args = parser.parse_args()

    if not args.filename:
        parser.print_help()
        print("\n[-] Please specify an input file to parse. "
              "Use -f <nmap_scan.xml> to specify the file\n")
        exit()
    if not args.ip_addresses and not args.csv and not args.print_all:
        parser.print_help()
        print("\n[-] Please choose an output option. Use -csv, -ip, or -p\n")
        exit()
    csv_name = args.csv
    main()
