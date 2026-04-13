"""
netatlas: CDP-based network discovery + HTML topology visualization.

This script logs into a seed Cisco IOS device via SSH, reads CDP neighbors,
and then "hops" to neighbors by running `ssh` from inside the device CLI
(nested SSH sessions). The resulting graph is written to `topology.json`
and rendered as a Cytoscape-based HTML file.
"""

import argparse
import getpass
import json
import time
import sys
import re
import logging
import warnings
import webbrowser
import os
import hashlib
from pathlib import Path
from netmiko import ConnectHandler
import base64

ANSI_ESCAPE_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
PROMPT_RE = re.compile(r"(?m)([^\r\n]+[>#])\s*$")

TOPOLOGY_MAP_TEMPLATE_PATH = Path(__file__).with_name("topology_map_template.html")
SSH_LOGIN_POLL_COUNT = 20
SSH_LOGIN_POLL_DELAY_SEC = 0.5


def get_image_data_uri(filepath: str) -> str:
    """Return a base64 data URI for a local image path (or empty string)."""
    if not os.path.exists(filepath):
        print(f" [!] Bild nicht gefunden: {filepath}")
        return ""
    
    with open(filepath, "rb") as image_file:
        encoded_string = base64.b64encode(image_file.read()).decode("utf-8")
        ext = os.path.splitext(filepath)[1][1:].lower() 
        mime_type = "image/svg+xml" if ext == "svg" else f"image/{ext}"
        return f"data:{mime_type};base64,{encoded_string}"

logging.getLogger('pyats').setLevel(logging.CRITICAL)
logging.getLogger('genie').setLevel(logging.CRITICAL)
logging.getLogger('unicon').setLevel(logging.CRITICAL)
warnings.filterwarnings('ignore')

# Global state
topology = {}
visited_hosts = set()  # Stores device hashes we've already seen.


def strip_ansi(text):
    """Remove ANSI escape sequences from text."""
    return ANSI_ESCAPE_RE.sub("", text)


def prompt_to_hostname(prompt):
    """Extract a hostname-like string from a Cisco-style CLI prompt."""
    prompt = strip_ansi(prompt).strip()
    prompt = prompt.rstrip("#>").strip()
    return prompt.split("(", 1)[0].strip()


def wait_for_prompt(conn, timeout=15, sleep=0.5):
    """
    Read channel output until a CLI prompt appears at the end of a line.

    This is used as a robust fallback for devices that print banners slowly or
    where ANSI sequences/paging confuse the default prompt detection.
    """
    output = ""
    deadline = time.time() + timeout

    while time.time() < deadline:
        chunk = conn.read_channel()
        if chunk:
            output += chunk
            clean_output = strip_ansi(output)
            match = PROMPT_RE.search(clean_output)
            if match:
                return match.group(1).strip(), clean_output

        conn.write_channel("\n")
        time.sleep(sleep)

    return None, strip_ansi(output)


def sync_base_prompt(conn, timeout=15):
    """
    Synchronize Netmiko's base prompt with a robust fallback.

    Netmiko's `set_base_prompt()` can fail on slow/chatty devices. If that
    happens we detect the prompt manually and set `conn.base_prompt`.
    """
    try:
        return conn.set_base_prompt()
    except Exception:
        prompt, output = wait_for_prompt(conn, timeout=timeout)
        if not prompt:
            raise ValueError(f"Pattern not detected: '(?:\\\\#|>)' in output.\nCaptured output:\n{output.strip()}")

        base_prompt = prompt_to_hostname(prompt)
        if not base_prompt:
            raise ValueError(f"Prompt could not be derived from output:\n{output.strip()}")

        conn.base_prompt = base_prompt
        return base_prompt

def parse_arguments():
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(description="Advanced L2/L3 Network Discovery (GNS3 Style)")
    parser.add_argument("-i", "--ip", required=True, help="Seed node management IP")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", help="SSH password (prompted if missing)")
    parser.add_argument("-e", "--enable", help="Enable secret (optional)")
    return parser.parse_args()

def get_device_hash(conn):
    """
    Compute a stable-ish device identifier based on interface BIAs.

    It runs `show interfaces`, collects the "bia" MACs from interfaces that are
    "up, line protocol is up", sorts them and hashes the concatenation.
    This is used to avoid revisiting the same physical device via different IPs.
    """
    try:
        output = conn.send_command("show interfaces")
    except Exception as e:
        print(f"  [!] Fehler beim Auslesen der Interfaces für Hash: {e}")
        return "error_" + str(time.time())

    macs = []
    is_up = False
    
    for line in output.splitlines():
        if " is up, line protocol is up" in line:
            is_up = True
        elif " is down" in line or " is administratively down" in line:
            is_up = False
            
        if is_up and "bia" in line:
            match = re.search(r'bia\s+([a-fA-F0-9\.]+)', line)
            if match:
                macs.append(match.group(1).lower())
            is_up = False
            
    if not macs:
        macs.append("no_up_interfaces_" + str(time.time()))
        
    macs.sort()
    mac_string = "".join(macs)
    return hashlib.sha256(mac_string.encode()).hexdigest()

def infer_remote_type(cdp_capabilities) -> str:
    """
    Infer a remote device type string from CDP capabilities.

    Capabilities may come back as a list or a string; we normalize it and check
    for the keywords "router" and "switch".
    """
    if isinstance(cdp_capabilities, list):
        caps_str = " ".join(cdp_capabilities).lower()
    else:
        caps_str = str(cdp_capabilities).lower()

    if "router" in caps_str:
        return "Router"
    if "switch" in caps_str:
        return "Switch"
    return "Unknown"

def dfs_discover(conn, current_ip, current_hostname, username, password, enable_secret):
    """
    Depth-first CDP discovery starting from the current device.

    How it works:
    - Reads local interface descriptions and IPs (best-effort).
    - Parses `show cdp neighbors detail` for neighbor management IPs.
    - "Hops" to neighbors by issuing `ssh -l user <ip>` inside the current CLI
      session (nested SSH), discovers recursively, then `exit`s back.
    """
    # Identify device by its interface MACs (so we don't loop forever).
    current_hash = get_device_hash(conn)
    
    if current_hash in visited_hosts:
        return current_hash
    
    visited_hosts.add(current_hash)
    print(f"[+] Analyzing: {current_hostname} ({current_ip}) -> Hash: {current_hash[:8]}...")
    
    sync_base_prompt(conn)
    
    intf_descriptions = {}
    try:
        desc_out = conn.send_command("show interfaces description", use_genie=True)
        if isinstance(desc_out, dict) and 'interfaces' in desc_out:
            for intf, data in desc_out['interfaces'].items():
                intf_descriptions[intf] = data.get('description', '')
    except Exception:
        pass 

    intf_ips = {}
    try:
        ip_out = conn.send_command("show ip interface brief", use_genie=True)
        if isinstance(ip_out, dict) and 'interface' in ip_out:
            for intf, data in ip_out['interface'].items():
                ip = data.get('ip_address', 'Unassigned')
                if ip and ip != 'unassigned':
                    intf_ips[intf] = ip
    except Exception:
        pass

    try:
        cdp_out = conn.send_command("show cdp neighbors detail", use_genie=True)
    except Exception as e:
        print(f"  [!] CDP parse error: {e}")
        return current_hash

    if not isinstance(cdp_out, dict) or 'index' not in cdp_out:
        return current_hash

    topology[current_hash] = {
        "hostname": current_hostname,  # Keep hostname for the UI.
        "management_ip": current_ip,
        "device_type": "Unknown",
        "interfaces": intf_ips,
        "descriptions": intf_descriptions,
        "neighbors": {}
    }

    neighbors_to_visit = []

    for idx, neighbor_data in cdp_out.get('index', {}).items():
        neigh_hostname = neighbor_data.get('device_id', '').split('.')[0]
        local_int = neighbor_data.get('local_interface', '')
        remote_int = neighbor_data.get('port_id', '')
        
        mgmt_addrs = neighbor_data.get('management_addresses', {})
        cdp_remote_ip = list(mgmt_addrs.keys())[0] if mgmt_addrs else None

        remote_type = infer_remote_type(neighbor_data.get('capabilities', ""))

        if not cdp_remote_ip:
            continue
            
        link_data = {
            "remote_hostname": neigh_hostname,
            "local_interface": local_int,
            "remote_interface": remote_int,
            "cdp_remote_ip": cdp_remote_ip,
            "remote_type": remote_type
        }
        
        neighbors_to_visit.append((neigh_hostname, cdp_remote_ip, link_data))

    for neigh_host, neigh_ip, link_data in neighbors_to_visit:
        
        known_ips = {data["management_ip"]: h for h, data in topology.items()}
        if neigh_ip in known_ips:
            neigh_hash = known_ips[neigh_ip]
            topology[current_hash]["neighbors"][neigh_hash] = link_data
            continue
            
        print(f"  -> SSH: {current_hostname} -> {neigh_host} ({neigh_ip})")
        
        conn.read_channel()
        conn.write_channel(f"ssh -l {username} {neigh_ip}\n")
        
        login_success = False
        for _ in range(SSH_LOGIN_POLL_COUNT):
            time.sleep(SSH_LOGIN_POLL_DELAY_SEC)
            chunk = conn.read_channel()
            if "yes/no" in chunk:
                conn.write_channel("yes\n")
            elif "sername:" in chunk:
                conn.write_channel(username + "\n")
            elif "assword:" in chunk:
                conn.write_channel(password + "\n")
                login_success = True
                break
            elif "Connection refused" in chunk or "unreachable" in chunk:
                break

        if not login_success:
            print(f"  [!] SSH failed: {neigh_host}")
            conn.write_channel("\x03")
            # Store an unreachable node with a synthetic id so it still renders.
            topology[current_hash]["neighbors"][f"unreachable_{neigh_host}"] = link_data
            continue
            
        time.sleep(2)
        conn.write_channel("\n")
        time.sleep(0.5)
        
        prompt, prompt_check = wait_for_prompt(conn, timeout=15)
        if prompt and prompt.endswith(">") and enable_secret:
            conn.write_channel("enable\n")
            enable_prompt, enable_output = wait_for_prompt(conn, timeout=10)
            if enable_prompt and enable_prompt.endswith("#"):
                pass
            elif "assword:" in enable_output:
                conn.write_channel(enable_secret + "\n")
                wait_for_prompt(conn, timeout=10)

        conn.write_channel("terminal length 0\n")
        time.sleep(0.5)
        conn.read_channel()
        
        neigh_hash = dfs_discover(conn, neigh_ip, neigh_host, username, password, enable_secret)
        
        if neigh_hash:
             topology[current_hash]["neighbors"][neigh_hash] = link_data
        
        print(f"  <- Return: {neigh_host} -> {current_hostname}")
        conn.write_channel("exit\n")
        time.sleep(1)
        conn.read_channel()
        sync_base_prompt(conn)
        
    return current_hash

def get_intf_details(host_data, intf_name):
    """Return (ip, description) for an interface name, with a fuzzy fallback."""
    if not host_data:
        return "Unassigned", ""
    interfaces = host_data.get("interfaces", {})
    descriptions = host_data.get("descriptions", {})
    
    if intf_name in interfaces:
        return interfaces[intf_name], descriptions.get(intf_name, "")
        
    match = re.search(r'([A-Za-z]+)\s*([\d\/\.]+)', intf_name)
    if match:
        prefix, port = match.groups()
        for k_intf, v_ip in interfaces.items():
            k_match = re.search(r'([A-Za-z]+)\s*([\d\/\.]+)', k_intf)
            if k_match:
                k_prefix, k_port = k_match.groups()
                if prefix[:2].lower() == k_prefix[:2].lower() and port == k_port:
                    return v_ip, descriptions.get(k_intf, "")
    return "Unassigned", ""

def load_topology_map_template() -> str:
    """Load the HTML template used for the Cytoscape topology map."""
    return TOPOLOGY_MAP_TEMPLATE_PATH.read_text(encoding="utf-8")

def generate_topology_map(topology_dict, output_file="topology_map.html"):
    """Render `topology_dict` into a Cytoscape HTML file and open it."""
    print(f"\n[*] Generating GNS3-style Cytoscape map: {output_file}")
    
    global_types = {}
    for host_hash, data in topology_dict.items():
        for neigh_hash, link_data in data.get("neighbors", {}).items():
            global_types[neigh_hash] = link_data.get("remote_type", "Unknown")

    cyto_elements = []

    # Data URIs for node icons.
    router_icon = get_image_data_uri("/home/benedikt/router.png")
    switch_icon = get_image_data_uri("/home/benedikt/switch.png")

    for node_hash, data in topology_dict.items():
        hostname = data.get("hostname", "Unknown")
        mgmt_ip = data.get("management_ip", "Unknown")
        dev_type = global_types.get(node_hash, "Unknown")
        
        node_label = f"{hostname}\n{mgmt_ip}"
        icon = switch_icon if dev_type == "Switch" else router_icon
        
        cyto_elements.append({
            "data": {
                "id": node_hash,
                "label": node_label,
                "image": icon,
                "status": "online"
            }
        })

    added_edges = set()
    for node_hash, data in topology_dict.items():
        hostname = data.get("hostname", "Unknown")
        
        for neigh_hash, link_data in data.get("neighbors", {}).items():
            
            if neigh_hash not in topology_dict:
                neigh_hostname = link_data.get("remote_hostname", "Unknown")
                remote_type = link_data.get("remote_type", "Unknown")
                icon = switch_icon if remote_type == "Switch" else router_icon
                
                if not any(e["data"].get("id") == neigh_hash for e in cyto_elements):
                    cyto_elements.append({
                        "data": {
                            "id": neigh_hash,
                            "label": f"{neigh_hostname}\nUnreachable",
                            "image": icon,
                            "status": "offline"
                        }
                    })
                
            edge_id = tuple(sorted((node_hash, neigh_hash)))
            if edge_id not in added_edges:
                local_int = link_data.get("local_interface", "")
                remote_int = link_data.get("remote_interface", "")
                
                local_ip, _ = get_intf_details(topology_dict.get(node_hash), local_int)
                remote_ip, _ = get_intf_details(topology_dict.get(neigh_hash), remote_int)
                
                src_label = f"{local_int}\n{local_ip}"
                tgt_label = f"{remote_int}\n{remote_ip}"
                
                cyto_elements.append({
                    "data": {
                        "source": node_hash,
                        "target": neigh_hash,
                        "sourceLabel": src_label,
                        "targetLabel": tgt_label
                    }
                })
                added_edges.add(edge_id)

    elements_json = json.dumps(cyto_elements, indent=2)

    template = load_topology_map_template()
    html_content = template.replace("__ELEMENTS_JSON__", elements_json)

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_content)
        
    print(f"[+] Done! Opening {output_file} in your browser...")
    filepath = "file://" + os.path.realpath(output_file)
    webbrowser.open(filepath)

def main():
    """Entrypoint: connect to seed device, discover, then write outputs."""
    args = parse_arguments()
    password = args.password or getpass.getpass(prompt="SSH Password: ")
    enable_secret = args.enable if args.enable else password

    device_params = {
        'device_type': 'cisco_ios',
        'host': args.ip,
        'username': args.username,
        'password': password,
        'secret': enable_secret,
    }

    print(f"[*] Initializing connection to seed node: {args.ip}")
    try:
        netmiko_conn = ConnectHandler(**device_params)
        netmiko_conn.enable()
        
        start_prompt = sync_base_prompt(netmiko_conn)
        start_hostname = prompt_to_hostname(start_prompt)
        
        print("-" * 50)
        dfs_discover(netmiko_conn, args.ip, start_hostname, args.username, password, enable_secret)
        print("-" * 50)
        
        netmiko_conn.disconnect()
        
        with open("topology.json", "w") as f:
            json.dump(topology, f, indent=2)
            
        generate_topology_map(topology)
        
    except Exception as e:
        print(f"[!] Initial connection failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
