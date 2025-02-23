def create_nodes(tx, infos):
    host = infos["host_info"]

    if infos["port_info"]:
        ports = infos["port_info"]
        for port in ports:
            insert_host_with_port(tx, host, port)
    else:
        insert_host_only(tx, host)


def insert_host_only(tx, host):
    tx.run(
        "MERGE(h:Host {ip: $ip, hostname: $hostname})",
        hostname=host["hostname"],
        ip=host["ip"],
    )


def insert_host_with_port(tx, host, port):
    tx.run(
        "MERGE(p:Port {port: $port, state: $state, protocol: $protocol, service: $service, sunrpcinfo: $sunrpcinfo, versioninfo: $versioninfo})"
        "MERGE(h:Host {ip: $ip, hostname: $hostname})"
        "MERGE (p)-[:OPEN]->(h)",
        port=port["no"],
        state=port["state"],
        protocol=port["protocol"],
        service=port["service"],
        sunrpcinfo=port["sunrpcinfo"],
        versioninfo=port["versioninfo"],
        hostname=host["hostname"],
        ip=host["ip"],
    )
