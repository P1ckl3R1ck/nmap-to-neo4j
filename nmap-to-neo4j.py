import argparse
import logging

from pathlib import Path
from sys import exit as sys_exit
from typing import Dict, List, Optional

import xmltodict
from neo4j import GraphDatabase

from queries import insert

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_arg_parser() -> argparse.ArgumentParser:

    parser = argparse.ArgumentParser(description="Nmap-to-Neo4j Graph Database Utility")
    parser.add_argument(
        "-b",
        "--bolt",
        action="store",
        dest="bolt",
        help="Address of your bolt connector (default: '127.0.0.1')",
        required=False,
        default="127.0.0.1",
    )
    parser.add_argument(
        "-u",
        "--username",
        action="store",
        dest="neo_user",
        help="Username of the Neo4j user (default: 'neo4j')",
        required=False,
        default="neo4j",
    )
    parser.add_argument(
        "-p",
        "--password",
        dest="neo_pass",
        help="Password of the Neo4j user",
        required=True,
    )
    parser.add_argument(
        "-P",
        "--port",
        dest="neo_port",
        help="Port of the bolt instance (default: 7687)",
        required=False,
        default="7687",
    )
    parser.add_argument(
        "-f",
        "--file",
        dest="nmap_file",
        help="Scan of the XML nmap file (-oX flag)",
        required=True,
    )
    parser.add_argument(
        "-ai",
        "--attacking-ip",
        dest="attacking_ip",
        help="IP address of the attacking machine to exclude from import",
        required=False,
        default=None,
    )
    return parser

def create_neo4j_driver(
    bolt: str, neo_port: str, neo_user: str, neo_pass: str
) -> GraphDatabase.driver:

    uri = f"neo4j://{bolt}:{neo_port}"
    driver = GraphDatabase.driver(uri, auth=(neo_user, neo_pass))

    return driver

def populate_neo4j_database(
    data: List[Dict], driver: GraphDatabase.driver, attacking_ip: Optional[str]
) -> None:

    with driver.session() as session:
        for entry in data:
            if entry["host_info"]["ip"] != attacking_ip:
                session.execute_write(insert.create_nodes, entry)

def parse_port_protocol_info_(port: Dict) -> Dict[str, str]:

    port_info = {
        "no": port["@portid"],
        "state": port["state"]["@state"],
        "protocol": port["@protocol"],
        "service": port["service"]["@name"],
        "sunrpcinfo": port["service"].get("@product", ""),
        "versioninfo": port["service"].get("@version", ""),
    }

    return port_info

def parse_port_protocol_info(data: Dict) -> List[Dict[str, str]]:

    if "port" in data["ports"]:
        ports = (
            [data["ports"]["port"]]
            if isinstance(data["ports"]["port"], dict)
            else data["ports"]["port"]
        )
        return [
            parse_port_protocol_info_(port)
            for port in ports
            if port["state"]["@state"] == "open"
        ]

    return []

def extract_nmap_host_information(data: Dict) -> Dict[str, Dict[str, str]]:

    hostname = ""
    if data.get("hostnames"):
        hostnames = data["hostnames"]
        hostname = (
            hostnames[0]["hostname"]["@name"]
            if isinstance(hostnames, list)
            else hostnames["hostname"]["@name"]
        )

    address = data["address"]["@addr"]

    return {
        "host_info": {"hostname": hostname, "ip": address},
        "port_info": parse_port_protocol_info(data),
    }

def parse_nmap_file(filename: str) -> List[Dict[str, Dict[str, str]]]:

    filename = Path(filename).resolve()

    try:
        with open(filename) as xml_file:
            xml_content = xml_file.read()
    except OSError as e:
        raise Exception(f"Failed to read nmap scan file: {filename}! {e}")

    try:
        xmljson = xmltodict.parse(xml_content)
    except xmltodict.expat.ExpatError as e:
        raise Exception(f"Failed to parse XML data: wrong format! {e}")

    hosts = xmljson.get("nmaprun", {}).get("host", [])
    if isinstance(hosts, dict) and len(hosts) > 0:
        return [extract_nmap_host_information(hosts)]
    elif isinstance(hosts, list) and len(hosts) > 0:
        return [extract_nmap_host_information(host) for host in hosts]
    return []

if __name__ == "__main__":

    arg_paser = create_arg_parser()
    args = arg_paser.parse_args()

    try:
        logger.info("Parsing nmap data...")
        parsed_nmap_data = parse_nmap_file(args.nmap_file)
        parsed_nmap_data_len = len(parsed_nmap_data)

        if parsed_nmap_data_len > 0:
            logger.info(f"Found {parsed_nmap_data_len} hosts")
        else:
            raise Exception("Failed to parse nmap information: no host found!")
    except Exception as e:
        logger.error(e)
        sys_exit(-1)

    driver = create_neo4j_driver(args.bolt, args.neo_port, args.neo_user, args.neo_pass)

    try:
        logger.info("Syncing...")
        populate_neo4j_database(parsed_nmap_data, driver, args.attacking_ip)
    except Exception as e:
        logger.error(e)
        sys_exit(-1)
    finally:
        logger.info("Done syncing")
