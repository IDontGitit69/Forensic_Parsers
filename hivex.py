#!/usr/bin/env python3
"""
test_hivex.py — Direct test of the hivex library against a real SYSTEM
hive, BEFORE we build any integration around it. Prints whatever it
actually finds for ComputerName and network interface IPs, using hivex's
own (more damage-tolerant) parsing.

Usage:
  python3 test_hivex.py /path/to/SYSTEM
"""

import sys
from pathlib import Path

try:
    import hivex
except ImportError:
    print("hivex not installed. On Ubuntu/Debian: sudo apt install python3-hivex")
    sys.exit(1)


def find_child(h, parent_node, name):
    """Case-insensitive child node lookup -- hivex's own get_child_node is
    case-insensitive per its docs, but being explicit here for clarity."""
    try:
        return h.node_get_child(parent_node, name)
    except RuntimeError:
        return None


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 test_hivex.py /path/to/SYSTEM")
        sys.exit(1)

    hive_path = Path(sys.argv[1])
    if not hive_path.exists():
        print(f"File not found: {hive_path}")
        sys.exit(1)

    print(f"Opening {hive_path} with hivex...")
    try:
        # write=False: we never want to modify evidence.
        # verbose/debug left off by default; flip to True if this fails
        # mysteriously and you want hivex's own diagnostic chatter.
        h = hivex.Hivex(str(hive_path), write=False)
    except RuntimeError as e:
        print(f"hivex FAILED to open the hive at all: {e}")
        sys.exit(1)

    print("Hive opened successfully.\n")

    root = h.root()

    # Find which ControlSetNNN is actually active via Select\Current
    current_cs = "001"
    select_node = find_child(h, root, "Select")
    if select_node:
        try:
            current_val = h.node_get_value(select_node, "Current")
            current_int = h.value_dword(current_val)
            current_cs = f"{current_int:03d}"
            print(f"Active ControlSet: ControlSet{current_cs} (from Select\\Current)")
        except RuntimeError as e:
            print(f"Could not read Select\\Current, defaulting to 001: {e}")
    else:
        print("Select key not found at all, defaulting to ControlSet001")

    print()

    # ── ComputerName ──────────────────────────────────────────────────────────
    print("=== ComputerName ===")
    path = ["ControlSet" + current_cs, "Control", "ComputerName", "ComputerName"]
    node = root
    found = True
    for part in path:
        node = find_child(h, node, part)
        if node is None:
            print(f"  Could not find subkey: {part}")
            found = False
            break

    if found:
        try:
            val = h.node_get_value(node, "ComputerName")
            name = h.value_string(val)
            print(f"  ComputerName = {name}")
        except RuntimeError as e:
            print(f"  Found the key but could not read ComputerName value: {e}")

    print()

    # ── Network interfaces ───────────────────────────────────────────────────
    print("=== Tcpip Interfaces ===")
    path = ["ControlSet" + current_cs, "Services", "Tcpip", "Parameters", "Interfaces"]
    node = root
    found = True
    for part in path:
        node = find_child(h, node, part)
        if node is None:
            print(f"  Could not find subkey: {part}")
            found = False
            break

    if found:
        children = h.node_children(node)
        print(f"  Found {len(children)} interface subkey(s)")
        for child in children:
            iface_name = h.node_name(child)
            print(f"\n  Interface: {iface_name}")
            for value_name in ("IPAddress", "DhcpIPAddress"):
                try:
                    val = h.node_get_value(child, value_name)
                except RuntimeError:
                    continue  # this value doesn't exist on this interface, normal

                # Don't rely on a specific REG_* constant name (varies by
                # hivex version/binding) -- just try the readers in order
                # and use whichever one doesn't raise.
                data = None
                try:
                    data = h.value_multiple_strings(val)
                except RuntimeError:
                    pass
                if data is None:
                    try:
                        data = h.value_string(val)
                    except RuntimeError:
                        pass

                if data is not None:
                    print(f"    {value_name} = {data}")
                else:
                    # Last resort: show the raw type code so we can see what
                    # we're actually dealing with if both readers failed.
                    try:
                        type_code, _ = h.value_type(val)
                        print(f"    {value_name} = <could not decode, raw type code {type_code}>")
                    except RuntimeError as e:
                        print(f"    {value_name} = <could not read at all: {e}>")


if __name__ == "__main__":
    main()
