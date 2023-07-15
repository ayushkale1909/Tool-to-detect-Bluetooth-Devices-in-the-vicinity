import os
import sys
import struct
import json
import numpy as np
import bluetooth._bluetooth as bluez  # low level bluetooth wrapper
import bluetooth  # Import pybluez library
import plotly.graph_objects as go

def setup_socket(sock):
    """Setup socket filter to receive only events related to the read_inquiry_mode command"""
    old_filter = sock.getsockopt(bluez.SOL_HCI, bluez.HCI_FILTER, 14)
    flt = bluez.hci_filter_new()
    opcode = bluez.cmd_opcode_pack(bluez.OGF_HOST_CTL, bluez.OCF_READ_INQUIRY_MODE)
    bluez.hci_filter_set_ptype(flt, bluez.HCI_EVENT_PKT)
    bluez.hci_filter_set_event(flt, bluez.EVT_CMD_COMPLETE)
    bluez.hci_filter_set_opcode(flt, opcode)
    sock.setsockopt(bluez.SOL_HCI, bluez.HCI_FILTER, flt)
    return old_filter
def read_inquiry_mode(sock):	#Setup socket filter to receive only events related to the read_inquiry_mode command

    old_filter = sock.getsockopt( bluez.SOL_HCI, bluez.HCI_FILTER, 14)

    flt = bluez.hci_filter_new()
    opcode = bluez.cmd_opcode_pack(bluez.OGF_HOST_CTL, 
            bluez.OCF_READ_INQUIRY_MODE)
    bluez.hci_filter_set_ptype(flt, bluez.HCI_EVENT_PKT)
    bluez.hci_filter_set_event(flt, bluez.EVT_CMD_COMPLETE);
    bluez.hci_filter_set_opcode(flt, opcode)
    sock.setsockopt( bluez.SOL_HCI, bluez.HCI_FILTER, flt )
    # first read the current inquiry mode.
    bluez.hci_send_cmd(sock, bluez.OGF_HOST_CTL, 
            bluez.OCF_READ_INQUIRY_MODE )

    pkt = sock.recv(255)

    status,mode = struct.unpack("xxxxxxBB", pkt)
    if status != 0: mode = -1

    sock.setsockopt( bluez.SOL_HCI, bluez.HCI_FILTER, old_filter )
    return mode

def write_inquiry_mode(sock, mode):	# save current filter
    
    old_filter = sock.getsockopt( bluez.SOL_HCI, bluez.HCI_FILTER, 14)

    
    flt = bluez.hci_filter_new()
    opcode = bluez.cmd_opcode_pack(bluez.OGF_HOST_CTL, 
            bluez.OCF_WRITE_INQUIRY_MODE)
    bluez.hci_filter_set_ptype(flt, bluez.HCI_EVENT_PKT)
    bluez.hci_filter_set_event(flt, bluez.EVT_CMD_COMPLETE);
    bluez.hci_filter_set_opcode(flt, opcode)
    sock.setsockopt( bluez.SOL_HCI, bluez.HCI_FILTER, flt )

    #send the command
    bluez.hci_send_cmd(sock, bluez.OGF_HOST_CTL, 
            bluez.OCF_WRITE_INQUIRY_MODE, struct.pack("B", mode) )

    pkt = sock.recv(255)

    status = struct.unpack("xxxxxxB", pkt)[0]
    # restore old filter
    sock.setsockopt( bluez.SOL_HCI, bluez.HCI_FILTER, old_filter )
    if status != 0: return -1
    return 0


def perform_device_inquiry(sock):
    """perform a device inquiry on bluetooth device"""
    # before the inquiry is performed, bluez should flush its cache of previously discovered devices
    old_filter = sock.getsockopt(bluez.SOL_HCI, bluez.HCI_FILTER, 14)
    flt = bluez.hci_filter_new()
    bluez.hci_filter_all_events(flt)
    bluez.hci_filter_set_ptype(flt, bluez.HCI_EVENT_PKT)
    sock.setsockopt(bluez.SOL_HCI, bluez.HCI_FILTER, flt)

    duration = 4
    max_responses = 255
    cmd_pkt = struct.pack("BBBBB", 0x33, 0x8b, 0x9e, duration, max_responses)
    bluez.hci_send_cmd(sock, bluez.OGF_LINK_CTL, bluez.OCF_INQUIRY, cmd_pkt)

    results = []
    done = False

    while not done:
        pkt = sock.recv(255)
        ptype, event, plen = struct.unpack("BBB", pkt[:3])
        if event == bluez.EVT_INQUIRY_RESULT_WITH_RSSI:
            pkt = pkt[3:]
            nrsp = bluetooth.get_byte(pkt[0])
            for i in range(nrsp):
                addr = bluez.ba2str(pkt[1 + 6 * i:1 + 6 * i + 6])
                rssi = bluetooth.byte_to_signed_int(
                    bluetooth.get_byte(pkt[1 + 13 * nrsp + i]))
                results.append((addr, rssi))
                print("[%s] RSSI: [%d]" % (addr, rssi))
        elif event == bluez.EVT_INQUIRY_COMPLETE:
            done = True
        elif event == bluez.EVT_CMD_STATUS:
            status, ncmd, opcode = struct.unpack("BBH", pkt[3:7])
            if status != 0:
                print("uh oh...")
                done = True
        elif event == bluez.EVT_INQUIRY_RESULT:
            pkt = pkt[3:]
            nrsp = bluetooth.get_byte(pkt[0])
            for i in range(nrsp):
                addr = bluez.ba2str(pkt[1 + 6 * i:1 + 6 * i + 6])
                results.append((addr, -1))
                print("[%s] (no RRSI)" % addr)
        else:
            print("unrecognized packet type 0x%02x" % ptype)
        print("event ", event)

    sock.setsockopt(bluez.SOL_HCI, bluez.HCI_FILTER, old_filter)
    return results

def plot_data(name_mac, output, mac_id_1, out_rssi):
    """Plot data"""
    theta = np.linspace(0, 360, len(output))
    x = output * np.cos(theta)
    y = output * np.sin(theta)
    fig = go.Figure(data=[go.Scatter(
        x=x, y=y, text=name_mac, textposition="bottom center",
        mode='markers+text', marker=dict(size=100, symbol='square'))
    ])
    fig2 = go.Figure(data=[go.Table(header=dict(values=['Names', 'Approx Distances(metres)', 'MAC addresses', 'RSSI']),
                                    cells=dict(values=[name_mac, output, mac_id_1, out_rssi]))
                          ])

    fig.update_xaxes(visible=False)
    fig.update_yaxes(visible=False)
    fig.update_layout(showlegend=False)
    fig.show()
    fig2.show()

def main():
    dev_id = 0
    try:
        sock = bluez.hci_open_dev(dev_id)
    except:
        print("Error accessing bluetooth device...")
        return

    try:
        mode = read_inquiry_mode(sock)
    except Exception as e:
        print("Error reading inquiry mode. Are you sure this is a bluetooth 1.2 device?")
        print(e)
        return

    print("Current inquiry mode is %d" % mode)

    if mode != 1:
        print("Writing inquiry mode...")
        try:
            result = write_inquiry_mode(sock, 1)
        except Exception as e:
            print("Error writing inquiry mode. Are you sure you're root?")
            print(e)
            return
        if result != 0:
            print("Error while setting inquiry mode")
        print("Result: %d" % result)

    rssi_devices = perform_device_inquiry(sock)
    discovered_devices = bluetooth.discover_devices(lookup_names=True, duration=5)

    # map addresses to names and RSSIs
    devices = [(name, addr, rssi) for (addr, rssi) in rssi_devices for name, _addr in discovered_devices if addr == _addr]

    # remaining code

if __name__ == "__main__":
    main()
