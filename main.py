import argparse
import json
from pyats.topology import loader
from genie.conf import Genie
from unicon.core.errors import ConnectionError
from collections import deque


def build_testbed(host, username, password, device_type="ios", proxy=None):
    """
    Baut dynamisch ein pyATS Testbed Dictionary.
    Optional mit Proxy (Jump Host).
    """
    device = {
        "os": device_type,
        "type": "router",
        "credentials": {
            "default": {
                "username": username,
                "password": password
            }
        },
        "connections": {
            "cli": {
                "protocol": "ssh",
                "ip": host,
                "arguments": {
                    "learn_hostname": True
                }
            }
        }
    }

    # Proxy Unterstützung (Jump Host)
    if proxy:
        device["connections"]["cli"]["proxy"] = proxy

    testbed_dict = {
        "devices": {
            host: device
        }
    }

    return loader.load(testbed_dict)


def discover(start_host, username, password, device_type):
    topology = {}
    visited = set()
    connected_devices = {}

    queue = deque()
    queue.append((start_host, None))  # (host, proxy)

    while queue:
        host, proxy = queue.popleft()
        print(host)

        if host in visited:
            continue

        print(f"[INFO] Verbinde zu {host} (Proxy: {proxy})")

        try:
            testbed = build_testbed(
                host,
                username,
                password,
                device_type=device_type,
                proxy=proxy
            )
            print(testbed)

            device = testbed.devices[host]
            device.connect(log_stdout=False)

            connected_devices[host] = device
            visited.add(host)
            topology[host] = []

            # CDP strukturiert parsen
            cdp_data = device.parse("show cdp neighbors detail")

            if "index" in cdp_data:
                for entry in cdp_data["index"].values():
                    neighbor_ip = entry.get("ip_address")
                    device_id = entry.get("device_id")
                    local_int = entry.get("local_interface")
                    remote_int = entry.get("port_id")

                    topology[host].append({
                        "neighbor_ip": neighbor_ip,
                        "device_id": device_id,
                        "local_interface": local_int,
                        "remote_interface": remote_int
                    })

                    if neighbor_ip and neighbor_ip not in visited:
                        # Aktuelles Gerät als Proxy für nächste Ebene
                        queue.append((neighbor_ip, host))

        except ConnectionError:
            print(f"[WARN] Keine Verbindung zu {host} möglich")
        except Exception as e:
            print(f"[ERROR] Fehler bei {host}: {e}")

    return topology


def main():
    parser = argparse.ArgumentParser(
        description="CDP Netzwerk Discovery Tool mit pyATS + Jump Host"
    )

    parser.add_argument("--host", required=True)
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--device-type", default="ios")
    parser.add_argument("--output", default="topology.json")

    args = parser.parse_args()

    topology = discover(
        args.host,
        args.username,
        args.password,
        args.device_type
    )

    print("\n--- Netzwerk Topologie ---")
    print(json.dumps(topology, indent=4))

    with open(args.output, "w") as f:
        json.dump(topology, f, indent=4)

    print(f"\n[INFO] Topologie gespeichert in {args.output}")


if __name__ == "__main__":
    main()
