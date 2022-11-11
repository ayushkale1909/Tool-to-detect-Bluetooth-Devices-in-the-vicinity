import json
import os
import sys
import struct
from unicodedata import name
import bluetooth._bluetooth as bluez #low level bluetooth wrapper
import bluetooth	#Import pybluez library
import numpy as np	

a=np.array=np.empty	
def printpacket(pkt):	
    for c in pkt:
        sys.stdout.write("%02x " % struct.unpack("B",c)[0])
    print() 


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

def device_inquiry_with_with_rssi(sock):	#perform a device inquiry on bluetooth device 
    old_filter = sock.getsockopt( bluez.SOL_HCI, bluez.HCI_FILTER, 14)
	
    #before the inquiry is performed, bluez should flush its cache of previously discovered devices
    flt = bluez.hci_filter_new()
    bluez.hci_filter_all_events(flt)
    bluez.hci_filter_set_ptype(flt, bluez.HCI_EVENT_PKT)
    sock.setsockopt( bluez.SOL_HCI, bluez.HCI_FILTER, flt )

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
                addr = bluez.ba2str( pkt[1+6*i:1+6*i+6] )
                rssi = bluetooth.byte_to_signed_int(
                        bluetooth.get_byte(pkt[1+13*nrsp+i]))
                results.append( ( addr, rssi ) )
                print("[%s] RSSI: [%d]" % (addr, rssi))
        elif event == bluez.EVT_INQUIRY_COMPLETE:
            done = True
        elif event == bluez.EVT_CMD_STATUS:
            status, ncmd, opcode = struct.unpack("BBH", pkt[3:7])
            if status != 0:
                print("uh oh...")
                printpacket(pkt[3:7])
                done = True
        elif event == bluez.EVT_INQUIRY_RESULT:
            pkt = pkt[3:]
            nrsp = bluetooth.get_byte(pkt[0])
            for i in range(nrsp):
                addr = bluez.ba2str( pkt[1+6*i:1+6*i+6] )
                results.append( ( addr, -1 ) )
                print("[%s] (no RRSI)" % addr)
        else:
            print("unrecognized packet type 0x%02x" % ptype)
        print("event ", event)


    
    sock.setsockopt( bluez.SOL_HCI, bluez.HCI_FILTER, old_filter )

    return results

dev_id = 0
try:	#Comment
    sock = bluez.hci_open_dev(dev_id)
except:
    print("error accessing bluetooth device...")
    sys.exit(1)

try:	#Error if not a bluetooth 1.2 device
    mode = read_inquiry_mode(sock)
except Exception as e:
    print("error reading inquiry mode.  ")
    print("Are you sure this a bluetooth 1.2 device?")
    print(e)
    sys.exit(1)
print("current inquiry mode is %d" % mode)

#Error in write inquiry mode if not runnning on root
if mode != 1:
    print("writing inquiry mode...")
    try:
        result = write_inquiry_mode(sock, 1)
    except Exception as e:
        print("error writing inquiry mode.  Are you sure you're root?")
        print(e)
        sys.exit(1)
    if result != 0:
        print("error while setting inquiry mode")
    print("result: %d" % result)

#Device inquiry with rssi stores in a numpy array
a=device_inquiry_with_with_rssi(sock)
out=a
le1=len(out)
out_2=np.asarray(out)
#using pybluez to discover name of devices
s=bluetooth.discover_devices(lookup_names=True,duration=5)
le2=len(s)
s_array=np.asarray(s)
b=np.empty
print(out_2)
print(s_array)
#storing the rssi value 
seen= set()
out_3=[]
for item in out_2:
    if seen.isdisjoint(item):
        out_3.append(item)
        seen.update(item)

print(out_3)
out_4=np.asarray(out_3)
out_rssi=out_4[:,1]
#Calculating the distances
final = out_rssi.astype(np.int64)
output = 10**((-69-(final))/20)
#Printing device related information
print("\n\n")
print("Final Distances calculated using RSSI is {}".format(output))
mac_id_1=out_4[:,0]
name_mac=s_array[:,1]
print("\n")
print("MAC ADDRESSES OF THE DEVICES FOUND\n")
print(mac_id_1)
print("\n")
print("NAMES OF DEVICES FOUND\n")
print(name_mac)
print("\n")
print("most accurate values of RSSI measured\n")
print(out_rssi)
#Plotting the device information as a table
#Plotting the bluetooth devices according to the distances 
theta=np.linspace(0,360,len(output))
x=output*np.cos(theta)
y=output*np.sin(theta)
import plotly.graph_objects as go
fig = go.Figure(data=[go.Scatter(
    x=x,y=y,text=name_mac,textposition="bottom center",
    mode='markers+text',marker = dict(size=100, symbol = 'square'))
    ])
fig2 = go.Figure(data=[go.Table(header=dict(values=['Names', 'Approx Distances(metres)','MAC addresses','RSSI']),
                 cells=dict(values=[name_mac,output,mac_id_1,out_rssi]))
                     ])

fig.update_xaxes(visible=False)
fig.update_yaxes(visible=False)
fig.update_layout(showlegend=False)
fig.show()
fig2.show()


