#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    #dest_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])
    dest_mac = data[0:6]
    src_mac = data[6:12]
    
    # Extract ethertype. Under 802.1Q, this may be the bytes from the VLAN TAG
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    # Check for VLAN tag (0x8100 in network byte order is b'\x81\x00')
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF  # extract the 12-bit VLAN ID
        ether_type = (data[16] << 8) + data[17]

    return dest_mac, src_mac, ether_type, vlan_id

def create_vlan_tag(vlan_id):
    # 0x8100 for the Ethertype for 802.1Q
    # vlan_id & 0x0FFF ensures that only the last 12 bits are used
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)

def resolve_vlan_type(vlan_tag):
    return 0 if vlan_tag == 'T' else int(vlan_tag)

def is_trunk_vlan(vlan_type):
    return vlan_type == 0

def is_unicast(mac_addr):
    return mac_addr[0] & 1 == 0

def trunk_packet_handling(dest_mac, vlan_id, interface, data, length, forwarding_table, vlan_map, interfaces, iface_status):
    untagged_data = data[:12] + data[16:]
    if is_unicast(dest_mac):
        if dest_mac in forwarding_table:
            vlan_path = resolve_vlan_type(vlan_map.get(get_interface_name(forwarding_table[dest_mac])))
            if vlan_path == 0:
                send_to_link(forwarding_table[dest_mac], length, data)
            else:
                send_to_link(forwarding_table[dest_mac], length - 4, untagged_data)
        else:
            for iface_num in interfaces:
                if iface_num != interface and iface_status[iface_num]:
                    vlan_path = resolve_vlan_type(vlan_map.get(get_interface_name(iface_num)))
                    if vlan_path == 0:
                        send_to_link(iface_num, length, data)
                    elif vlan_path == vlan_id:
                        send_to_link(iface_num, length - 4, untagged_data)
    else:
        for iface_num in interfaces:
            if iface_num != interface and iface_status[iface_num]:
                vlan_path = resolve_vlan_type(vlan_map.get(get_interface_name(iface_num)))
                if vlan_path == 0:
                    send_to_link(iface_num, length, data)
                elif vlan_path == vlan_id:
                    send_to_link(iface_num, length - 4, untagged_data)

def access_packet_handling(dest_mac, vlan_id, interface, data, length, forwarding_table, vlan_map, interfaces, iface_status):
    if is_unicast(dest_mac):
        if dest_mac in forwarding_table:
            vlan_path = resolve_vlan_type(vlan_map.get(get_interface_name(forwarding_table[dest_mac])))
            if vlan_path == 0:
                tagged_frame = data[:12] + create_vlan_tag(vlan_id) + data[12:]
                send_to_link(forwarding_table[dest_mac], length + 4, tagged_frame)
            else:
                send_to_link(forwarding_table[dest_mac], length, data)
        else:
            for iface_num in interfaces:
                if iface_num != interface and iface_status[iface_num]:
                    vlan_path = resolve_vlan_type(vlan_map.get(get_interface_name(iface_num)))
                    if vlan_path == 0:
                        tagged_frame = data[:12] + create_vlan_tag(vlan_id) + data[12:]
                        send_to_link(iface_num, length + 4, tagged_frame)
                    elif vlan_path == vlan_id:
                        send_to_link(iface_num, length, data)
    else:
        for iface_num in interfaces:
            if iface_num != interface and iface_status[iface_num]:
                vlan_path = resolve_vlan_type(vlan_map.get(get_interface_name(iface_num)))
                if vlan_path == 0:
                    tagged_frame = data[:12] + create_vlan_tag(vlan_id) + data[12:]
                    send_to_link(iface_num, length + 4, tagged_frame)
                elif vlan_path == vlan_id:
                    send_to_link(iface_num, length, data)

def send_bdpu_every_sec():
    global root_bridge_id, root_cost_path, bridge_id
    global interfaces, iface_status, vlan_map, forwarding_table
    while True:
        if bridge_id == root_bridge_id:
            for interface in interfaces:
                if vlan_map.get(get_interface_name(interface)) == 'T':
                    multicast_mac = struct.pack('!BBBBBB', 0x01, 0x80, 0xc2, 0x00, 0x00, 0x00)
                    bridge_id_pack = struct.pack('!q', bridge_id)
                    root_id_pack = struct.pack('!q', root_bridge_id)
                    cost_pack = struct.pack('!I', root_cost_path)
                    data = multicast_mac + bridge_id_pack + root_id_pack + cost_pack
                    send_to_link(interface, len(data), data)
        time.sleep(1)

def initialize_resources():
    forwarding_table = {}
    vlan_map = {}
    switch_id = sys.argv[1]
    bridge_id = root_bridge_id = -1
    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)
    iface_status = [True] * num_interfaces

    config_path = f'configs/switch{switch_id}.cfg'
    with open(config_path, 'r') as config_file:
        bridge_id = int(config_file.readline().strip())
        root_bridge_id = bridge_id
        root_cost_path = 0

        for line in config_file:
            line = line.strip()
            vlan_map.update({line.split()[0]: line.split()[1]})

    return forwarding_table, vlan_map, switch_id, bridge_id, root_bridge_id, root_cost_path, num_interfaces, interfaces, iface_status

def main():
    global root_bridge_id, root_cost_path, bridge_id
    global interfaces, iface_status, vlan_map, forwarding_table
    forwarding_table, vlan_map, switch_id, bridge_id, root_bridge_id, root_cost_path, num_interfaces, interfaces, iface_status = initialize_resources()
    root_link_iface = None

    t = threading.Thread(target=send_bdpu_every_sec)
    t.start()

    while True:
        interface, data, length = recv_from_any_link()
        if iface_status[interface]:
            multicast_mac = data[:6]

            if multicast_mac == b'\x01\x80\xc2\x00\x00\x00':
                bpdu_source_bid = int.from_bytes(data[6:14], byteorder='big')
                bpdu_root_bid = int.from_bytes(data[14:22], byteorder='big')
                bpdu_path_cost = int.from_bytes(data[22:26], byteorder='big')

                previous_root_status = (bridge_id == root_bridge_id)

                if bpdu_root_bid < root_bridge_id:
                    root_bridge_id = bpdu_root_bid
                    root_cost_path = bpdu_path_cost + 10
                    root_link_iface = interface

                    if previous_root_status:
                        for iface_num in interfaces:
                            if iface_num != root_link_iface and vlan_map.get(get_interface_name(iface_num)) == 'T':
                                iface_status[iface_num] = False

                    if not iface_status[root_link_iface]:
                        iface_status[root_link_iface] = True

                    multicast_mac = struct.pack('!BBBBBB', 0x01, 0x80, 0xc3, 0x00, 0x00, 0x00)
                    bridge_id_pack = struct.pack('!q', bridge_id)
                    root_id_pack = struct.pack('!q', root_bridge_id)
                    cost_pack = struct.pack('!I', root_cost_path)
                    data = multicast_mac + bridge_id_pack + root_id_pack + cost_pack
                    for iface_num in interfaces:
                        if iface_num != root_link_iface and vlan_map.get(get_interface_name(iface_num)) == 'T':
                            send_to_link(iface_num, len(data), data)

                elif bpdu_root_bid == root_bridge_id:
                    if interface == root_link_iface and bpdu_path_cost + 10 < root_cost_path:
                        root_cost_path = bpdu_path_cost + 10
                    elif interface != root_link_iface and bpdu_path_cost > root_cost_path:
                        iface_status[interface] = True

                elif bpdu_source_bid == bridge_id:
                    iface_status[interface] = False

                if bridge_id == root_bridge_id:
                    for iface_num in interfaces:
                        if iface_num != root_link_iface and vlan_map.get(get_interface_name(iface_num)) == 'T':
                            iface_status[iface_num] = True
                continue

        dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)
        if vlan_id == -1:
            vlan_id = resolve_vlan_type(vlan_map.get(get_interface_name(interface)))

        forwarding_table[src_mac] = interface

        vlan_source = resolve_vlan_type(vlan_map.get(get_interface_name(interface)))
        if is_trunk_vlan(vlan_source):
            trunk_packet_handling(dest_mac, vlan_id, interface, data, length, forwarding_table, vlan_map, interfaces, iface_status)
        else:
            access_packet_handling(dest_mac, vlan_id, interface, data, length, forwarding_table, vlan_map, interfaces, iface_status)

if __name__ == "__main__":
    main()
