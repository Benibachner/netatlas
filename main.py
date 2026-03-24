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
import base64
from netmiko import ConnectHandler
from pyvis.network import Network

# --- FIX: Suppress noisy pyATS / Genie / Unicon Logs ---
logging.getLogger('pyats').setLevel(logging.CRITICAL)
logging.getLogger('genie').setLevel(logging.CRITICAL)
logging.getLogger('unicon').setLevel(logging.CRITICAL)
warnings.filterwarnings('ignore')

# Globale Variablen
topology = {}
visited_hosts = set()

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

def parse_arguments():
    parser = argparse.ArgumentParser(description="Advanced L2/L3 Network Discovery (PyVis)")
    parser.add_argument("-i", "--ip", required=True, help="Seed node management IP")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", help="SSH password (prompted if missing)")
    parser.add_argument("-e", "--enable", help="Enable secret (optional)")
    return parser.parse_args()

def dfs_discover(conn, current_ip, current_hostname, username, password, enable_secret):
    if current_hostname in visited_hosts:
        return
    
    visited_hosts.add(current_hostname)
    print(f"[+] Analyzing: {current_hostname} ({current_ip})")
    
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
        return

    if not isinstance(cdp_out, dict) or 'index' not in cdp_out:
        return

    topology[current_hostname] = {
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

        caps = neighbor_data.get('capabilities', '')
        remote_type = "Unknown"
        if "Router" in caps or "R" in caps:
            remote_type = "Router"
        elif "Switch" in caps or "S" in caps:
            remote_type = "Switch"

        if not cdp_remote_ip:
            continue
            
        topology[current_hostname]["neighbors"][neigh_hostname] = {
            "local_interface": local_int,
            "remote_interface": remote_int,
            "cdp_remote_ip": cdp_remote_ip,
            "remote_type": remote_type
        }
        
        if neigh_hostname not in visited_hosts:
            neighbors_to_visit.append((neigh_hostname, cdp_remote_ip))

    for neigh_host, neigh_ip in neighbors_to_visit:
        if neigh_host in visited_hosts:
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
        
        dfs_discover(conn, neigh_ip, neigh_host, username, password, enable_secret)
        
        print(f"  <- Return: {neigh_host} -> {current_hostname}")
        conn.write_channel("exit\n")
        time.sleep(1)
        conn.read_channel()
        conn.set_base_prompt()

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

def generate_topology_map_pyvis(topology_dict, output_file="topology_map.html"):
    print(f"\n[*] Generating PyVis map: {output_file}")
    
    # Init PyVis Network
    net = Network(height="100vh", width="100%", bgcolor="#ffffff", font_color="#333", directed=False)
    
    global_types = {}
    for host, data in topology_dict.items():
        for neigh, link_data in data.get("neighbors", {}).items():
            global_types[neigh] = link_data.get("remote_type", "Unknown")

    # Icons (Pfade anpassen!)
    router_icon = get_image_data_uri("/home/benedikt/router.png")
    switch_icon = get_image_data_uri("/home/benedikt/switch.png")

    added_nodes = set()

    # 1. Nodes generieren
    for hostname, data in topology_dict.items():
        mgmt_ip = data.get("management_ip", "Unknown")
        dev_type = global_types.get(hostname, "Router")
        
        node_label = f"{hostname}\n({mgmt_ip})"
        # FIX: Hover-Information für den Node hinzugefügt (title)
        node_hover = f"Hostname: {hostname}\nManagement IP: {mgmt_ip}\nType: {dev_type}"
        
        icon = router_icon if dev_type == "Router" else switch_icon
        
        net.add_node(hostname, 
                     label=node_label, 
                     title=node_hover, # Das hier ermöglicht das Hovern auf Nodes
                     shape='image', 
                     image=icon, 
                     size=40, 
                     font={'size': 14, 'face': 'sans-serif', 'multi': True, 'align': 'center'})
        added_nodes.add(hostname)

    # 2. Edges generieren
    added_edges = set()
    for hostname, data in topology_dict.items():
        for neighbor, link_data in data.get("neighbors", {}).items():
            
            if neighbor not in added_nodes:
                remote_type = link_data.get("remote_type", "Unknown")
                icon = router_icon if remote_type == "Router" else switch_icon
                # FIX: Auch für unerreichbare Nodes Tooltips hinzufügen
                net.add_node(neighbor, 
                             label=f"{neighbor}\n(Unreachable)", 
                             title=f"Node {neighbor} was detected via CDP but not reached via SSH",
                             shape='image', 
                             image=icon, 
                             size=40, 
                             font={'color': 'red'})
                added_nodes.add(neighbor)
                
            edge_id = tuple(sorted((hostname, neighbor)))
            if edge_id not in added_edges:
                local_int = link_data.get("local_interface", "")
                remote_int = link_data.get("remote_interface", "")
                
                local_ip, _ = get_intf_details(topology_dict.get(hostname), local_int)
                remote_ip, _ = get_intf_details(topology_dict.get(neighbor), remote_int)
                
                edge_label = f"{local_int} ↔ {remote_int}"
                # FIX: Title für Edges (hast du bereits, stellen wir sicher, dass es sauber ist)
                hover_info = f"Link Details:\n{hostname} ({local_int}): {local_ip}\n{neighbor} ({remote_int}): {remote_ip}"
                
                net.add_edge(hostname, neighbor, label=edge_label, title=hover_info, color="#999999", width=2, font={'size': 10, 'align': 'horizontal'})
                added_edges.add(edge_id)

    # FIX: Interaction-Block hinzugefügt, um Hover explizit zu erlauben
    net.set_options("""
    var options = {
      "interaction": {
        "hover": true,
        "tooltipDelay": 200,
        "hideEdgesOnDrag": false
      },
      "physics": {
        "solver": "repulsion",
        "repulsion": {
          "centralGravity": 0.0,
          "springLength": 350,
          "springConstant": 0.05,
          "nodeDistance": 300,
          "damping": 0.09
        },
        "minVelocity": 0.75
      },
      "edges": {
        "smooth": false
      }
    }
    """)

    net.write_html(output_file)
    print(f"[+] Done! Opening {output_file}...")
    webbrowser.open("file://" + os.path.realpath(output_file))

    # Stabile PyVis/Vis.js Physik-Optionen (Repulsion pusht die Knoten hart auseinander)
    net.set_options("""
    var options = {
      "physics": {
        "solver": "repulsion",
        "repulsion": {
          "centralGravity": 0.0,
          "springLength": 350,
          "springConstant": 0.05,
          "nodeDistance": 300,
          "damping": 0.09
        },
        "minVelocity": 0.75
      },
      "edges": {
        "smooth": false
      }
    }
    """)

    # HTML speichern (PyVis nutzt standardmäßig UTF-8)
    net.write_html(output_file)
    
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
            
        # Aufruf der neuen PyVis-Funktion
        generate_topology_map_pyvis(topology)
        
    except Exception as e:
        print(f"[!] Initial connection failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
