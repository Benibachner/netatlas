# netatlas

CDP-based network discovery and topology visualization for Cisco IOS-style devices.

## What it does

- Connects to a seed device via SSH (Netmiko).
- Uses `show cdp neighbors detail` to find neighbors.
- Chains SSH sessions by running `ssh -l <user> <neighbor-ip>` from inside the
  current device CLI (nested SSH), then returns with `exit`.
- Writes the discovered graph to `topology.json`.
- Renders an interactive topology map to `topology_map.html` (Cytoscape) and
  opens it in your browser.

## Usage

```bash
python main.py -i <seed-ip> -u <username>
# optionally:
#   -p <password>
#   -e <enable-secret>
```

If `-p` is not provided you will be prompted. If `-e` is not provided, the
script currently uses the SSH password as enable secret.

## Outputs

- `topology.json`: raw discovery data keyed by an internal device hash
  (derived from interface BIAs).
- `topology_map.html`: rendered map using `topology_map_template.html`.

## Notes / assumptions

- CDP must be enabled and reachable across links you want to discover.
- The script expects Cisco IOS-like prompts and CLI behavior.
- The HTML map embeds icon images as data URIs. The icon paths are currently
  hard-coded in `main.py`:
  - `/home/benedikt/router.png`
  - `/home/benedikt/switch.png`
