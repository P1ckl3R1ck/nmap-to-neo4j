import argparse
import re
import xmltodict

from neo4j import GraphDatabase
from os import path as os_path
from sys import exit as sys_exit

from queries import insert

def create_arg_parser():

    parser = argparse.ArgumentParser(description="Nmap-to-Neo4j Graph Database Utility")
    parser.add_argument(
        "-b",
        "--bolt",
        action="store",
        dest="bolt",
        help="Address of your bolt connector. Default, '127.0.0.1'",
        required=False,
        default="127.0.0.1",
    )
    parser.add_argument(
        "-u",
        "--username",
        action="store",
        dest="neo_user",
        help="Username of the Neo4j user.  Default, 'neo4j'.",
        required=False,
        default="neo4j",
    )
    parser.add_argument(
        "-p",
        "--password",
        dest="neo_pass",
        help="Password of the Neo4j user.",
        required=True,
    )
    parser.add_argument(
        "-P",
        "--port",
        dest="neo_port",
        help="Port of the bolt instance if not 7687.",
        required=False,
        default="7687",
    )
    parser.add_argument(
        "-f",
        "--file",
        dest="nmap_file",
        help="Scan of the XML nmap file (-oX flag).",
        required=True,
    )
    parser.add_argument(
        "-ai",
        "--attacking-ip",
        dest="attacking_ip",
        help="IP address of the attacking machine to exclude from import.",
        required=False,
        default=None,
    )
    return parser

def create_neo4j_driver(bolt, neo_port, neo_user, neo_pass):

    uri = "neo4j://{}:{}".format(bolt, neo_port)
    driver = GraphDatabase.driver(uri, auth=(neo_user, neo_pass))

    return driver

def populate_neo4j_database(data, driver, attacking_ip):

    session = driver.session()
    for entry in data:
        if entry['host_info']['ip'] != attacking_ip:
            session.execute_write(insert.create_nodes, entry)

def parse_port_protocol_info_(port):

    port_info = {}

    port_info['no'] = port['@portid']
    port_info['state'] = port['state']['@state']
    port_info['protocol'] = port['@protocol']
    port_info['service'] = port['service']['@name']

    if '@product' in port['service']:
        port_info['sunrpcinfo'] = port['service']['@product']
        port_info['versioninfo'] = port['service']['@version']
    else:
        port_info['sunrpcinfo'] = ''
        port_info['versioninfo'] = ''

    return port_info

def parse_port_protocol_info(data):

    details = []

    if 'port' in data['ports'].keys():

        if isinstance(data['ports']['port'], dict):
            ports = [data['ports']['port']]
        elif isinstance(data['ports']['port'], list):
            ports = data['ports']['port']
        else:
            raise Exception("Failed to parse nmap information : port not found !")

        for port in ports:
            if (port['state']['@state'] == "open") :
                port_info = parse_port_protocol_info_(port)
                details.append(port_info)
            
        return details

    else:
        return None

def extract_nmap_host_information(data):

    if data['hostnames']:
        if isinstance(data['hostnames'], dict):
            hostname = data['hostnames']['hostname']['@name']
        elif isinstance(data['hostnames'], list):
            hostname = data['hostnames'][0]['hostname']['@name']
    else:
        hostname = ''

    address = data['address']['@addr']

    host = {
        'host_info': {
            'hostname': hostname,
            'ip': address
        },
        'port_info': parse_port_protocol_info(data)
    }

    return host

def parse_nmap_file(filename):

    res = []
    filename = os_path.abspath(filename)

    try:
        xml_file = open(filename)
        xml_content = xml_file.read()
        xml_file.close()
    except:
        raise Exception(f"Failed to read nmap scan file : {filename} !")

    try:
        xmljson = xmltodict.parse(xml_content)
    except:
        raise Exception(f"Failed to parse XML data : wrong format !")

    hosts = xmljson['nmaprun']['host']

    for host in hosts :
        res.append(extract_nmap_host_information(host))

    return res

if __name__ == "__main__":

    arg_paser = create_arg_parser()
    args = arg_paser.parse_args()

    try:
        parse_nmap_file(args.nmap_file)
        print("[*] Parsing nmap data...")
        parsed_nmap_data = parse_nmap_file(args.nmap_file)
        parsed_nmap_data_len = len(parsed_nmap_data)

        if parsed_nmap_data_len > 0:
            print(f"[+] Found {parsed_nmap_data_len} hosts")
        else: 
            raise Exception("Failed to parse nmap information : no host found !")
    except Exception as e:
        print(f"[!] {e}")
        sys_exit(-1)

    driver = create_neo4j_driver(args.bolt, args.neo_port, args.neo_user, args.neo_pass)

    try:
        print("[*] Syncing...")
        populate_neo4j_database(parsed_nmap_data, driver, args.attacking_ip)
    except Exception as e:
        print(f"[!] {e}")
        sys_exit(-1)
    finally:
        print("[+] Done syncing")
