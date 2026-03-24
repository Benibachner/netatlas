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
from netmiko import ConnectHandler
import base64

def get_image_data_uri(filepath):
    """Wandelt ein lokales Bild in eine Base64 Data URI um."""
    if not os.path.exists(filepath):
        print(f" [!] Bild nicht gefunden: {filepath}")
        return ""
    
    with open(filepath, "rb") as image_file:
        encoded_string = base64.b64encode(image_file.read()).decode("utf-8")
        ext = os.path.splitext(filepath)[1][1:].lower() 
        mime_type = "image/svg+xml" if ext == "svg" else f"image/{ext}"
        return f"data:{mime_type};base64,{encoded_string}"

# --- FIX: Suppress noisy pyATS / Genie / Unicon Logs ---
logging.getLogger('pyats').setLevel(logging.CRITICAL)
logging.getLogger('genie').setLevel(logging.CRITICAL)
logging.getLogger('unicon').setLevel(logging.CRITICAL)
warnings.filterwarnings('ignore')

# Globale Variablen
topology = {}
visited_hosts = set() # Speichert nun die Hashes

def parse_arguments():
    parser = argparse.ArgumentParser(description="Advanced L2/L3 Network Discovery (GNS3 Style)")
    parser.add_argument("-i", "--ip", required=True, help="Seed node management IP")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", help="SSH password (prompted if missing)")
    parser.add_argument("-e", "--enable", help="Enable secret (optional)")
    return parser.parse_args()

def get_device_hash(conn):
    """
    Holt 'show interfaces', filtert die 'up' Interfaces und deren BIA.
    Generiert daraus einen SHA256 Hash zur eindeutigen Identifikation.
    Netmiko behandelt das Paging (--More--) hierbei automatisch.
    """
    try:
        output = conn.send_command("show interfaces")
    except Exception as e:
        print(f"  [!] Fehler beim Auslesen der Interfaces für Hash: {e}")
        return "error_" + str(time.time())

    macs = []
    is_up = False
    
    for line in output.splitlines():
        # Prüfe ob das Interface up ist
        if " is up, line protocol is up" in line:
            is_up = True
        elif " is down" in line or " is administratively down" in line:
            is_up = False
            
        # Wenn up, suche nach BIA
        if is_up and "bia" in line:
            match = re.search(r'bia\s+([a-fA-F0-9\.]+)', line)
            if match:
                macs.append(match.group(1).lower())
            is_up = False # Reset bis zum nächsten Interface
            
    if not macs:
        # Fallback, falls absolut kein Interface "up" ist (z.B. Management Port only)
        macs.append("no_up_interfaces_" + str(time.time()))
        
    macs.sort()
    mac_string = "".join(macs)
    return hashlib.sha256(mac_string.encode()).hexdigest()

def dfs_discover(conn, current_ip, current_hostname, username, password, enable_secret):
    # 1. Gerät anhand seiner BIA-MACs identifizieren
    current_hash = get_device_hash(conn)
    
    if current_hash in visited_hosts:
        return current_hash
    
    visited_hosts.add(current_hash)
    print(f"[+] Analyzing: {current_hostname} ({current_ip}) -> Hash: {current_hash[:8]}...")
    
    conn.set_base_prompt()
    
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
        "hostname": current_hostname, # Hostname für GUI behalten
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

        caps = neighbor_data.get('capabilities', "")

        # Normalize to string
        if isinstance(caps, list):
            caps_str = " ".join(caps).lower()
        else:
            caps_str = str(caps).lower()

        remote_type = "Unknown"

        # Strikte Unterscheidung: Switch vs Router
        if "switch" in caps_str:
            remote_type = "Switch"
        elif "router" in caps_str:
            remote_type = "Router"

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
        
        # Effizienz-Check: Haben wir diese IP schon im Dictionary als Hash?
        known_ips = {data["management_ip"]: h for h, data in topology.items()}
        if neigh_ip in known_ips:
            neigh_hash = known_ips[neigh_ip]
            topology[current_hash]["neighbors"][neigh_hash] = link_data
            continue
            
        print(f"  -> SSH: {current_hostname} -> {neigh_host} ({neigh_ip})")
        
        conn.read_channel()
        conn.write_channel(f"ssh -l {username} {neigh_ip}\n")
        
        login_success = False
        for _ in range(20):
            time.sleep(0.5)
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
            # Unreachable Node mit Fake-ID speichern, damit er gezeichnet wird
            topology[current_hash]["neighbors"][f"unreachable_{neigh_host}"] = link_data
            continue
            
        time.sleep(2)
        conn.write_channel("\n")
        time.sleep(0.5)
        
        prompt_check = conn.read_channel()
        if ">" in prompt_check and enable_secret:
            conn.write_channel("enable\n")
            time.sleep(1)
            conn.write_channel(enable_secret + "\n")
            time.sleep(1)
        
        conn.write_channel("terminal length 0\n")
        time.sleep(0.5)
        conn.read_channel()
        
        # Rekursion - gibt den Hash des Nachbarn zurück
        neigh_hash = dfs_discover(conn, neigh_ip, neigh_host, username, password, enable_secret)
        
        if neigh_hash:
             topology[current_hash]["neighbors"][neigh_hash] = link_data
        
        print(f"  <- Return: {neigh_host} -> {current_hostname}")
        conn.write_channel("exit\n")
        time.sleep(1)
        conn.read_channel()
        conn.set_base_prompt()
        
    return current_hash

def get_intf_details(host_data, intf_name):
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

def generate_topology_map(topology_dict, output_file="topology_map.html"):
    print(f"\n[*] Generating GNS3-style Cytoscape map: {output_file}")
    
    global_types = {}
    for host_hash, data in topology_dict.items():
        for neigh_hash, link_data in data.get("neighbors", {}).items():
            global_types[neigh_hash] = link_data.get("remote_type", "Unknown")

    cyto_elements = []

    # SVG Data URIs für die Icons (Diese kannst du durch Links zu eigenen Bildern austauschen)
    router_icon = get_image_data_uri("/home/benedikt/router.png")
    switch_icon = get_image_data_uri("/home/benedikt/switch.png")

    # 1. Nodes generieren
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

    # 2. Edges generieren
    added_edges = set()
    for node_hash, data in topology_dict.items():
        hostname = data.get("hostname", "Unknown")
        
        for neigh_hash, link_data in data.get("neighbors", {}).items():
            
            # Fehlende (unerreichbare) Nodes ergänzen
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
                
                # GNS3 Style: Kurze Namen (z.B. Gi0/0) + IP
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

    # HTML mit Cytoscape.js
    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>GNS3 Style Topology</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.26.0/cytoscape.min.js"></script>
    <style>
        body {{ margin: 0; padding: 0; background-color: #ffffff; font-family: sans-serif; }}
        #cy {{ width: 100vw; height: 100vh; display: block; }}
        #title {{ position: absolute; top: 10px; left: 20px; z-index: 10; background: rgba(255,255,255,0.8); padding: 10px; border-radius: 5px; }}
    </style>
</head>
<body>
    <div id="title"><h2>L3 Network Topology</h2><p>Drag nodes to arrange.</p></div>
    <div id="cy"></div>

    <script>
        var elements = {elements_json};

        var cy = cytoscape({{
            container: document.getElementById('cy'),
            elements: elements,
            style: [
                {{
                    selector: 'node',
                    style: {{
                        /* GNS3 Style Node */
                        'background-image': 'data(image)',
                        'background-fit': 'contain',
                        'background-color': 'transparent',
                        'border-width': 0,
                        'background-opacity': 0,
                        'width': 60,
                        'height': 60,
                        'label': 'data(label)',
                        'text-valign': 'bottom',
                        'text-halign': 'center',
                        'text-margin-y': 5,
                        'font-size': 12,
                        'font-weight': 'bold',
                        'text-wrap': 'wrap'
                    }}
                }},
                {{
                    selector: 'node[status="offline"]',
                    style: {{ 'opacity': 0.4 }}
                }},
                {{
                    selector: 'edge',
                    style: {{
                        /* Geradlinige Verbindungen (Keine Ecken) */
                        'curve-style': 'straight',
                        'width': 2,
                        'line-color': '#999',
                        
                        /* Labels direkt an den Routern (Source & Target) */
                        'source-label': 'data(sourceLabel)',
                        'target-label': 'data(targetLabel)',
                        
                        /* Abstand der Labels vom Router-Icon (in Pixeln) */
                        'source-text-offset': 60,
                        'target-text-offset': 60,
                        
                        /* Text über der Linie rotieren */
                        'edge-text-rotation': 'autorotate',
                        'text-margin-y': -10,
                        'font-size': 10,
                        'color': '#333',
                        'text-background-color': '#fff',
                        'text-background-opacity': 0.7,
                        'text-wrap': 'wrap'
                    }}
                }}
            ],
            layout: {{
                name: 'cose',
                nodeDimensionsIncludeLabels: true,
                idealEdgeLength: 10000,
                nodeRepulsion: 800000,
                padding: 100,
                componentSpacing: 200
            }}
        }});
    </script>
</body>
</html>
"""

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_content)
        
    print(f"[+] Done! Opening {output_file} in your default browser...")
    filepath = "file://" + os.path.realpath(output_file)
    webbrowser.open(filepath)

def main():
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
        
        start_prompt = netmiko_conn.find_prompt()
        start_hostname = start_prompt.replace("#", "").replace(">", "").strip()
        
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
