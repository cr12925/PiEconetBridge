#!/usr/bin/python3
#   (c) 2025 Chris Royle
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <https://www.gnu.org/licenses/>.

import time
import sys
import re
import threading
import socket
import os

# machinePeek reply data
PEEK_HW=0xEEE0
PEEK_VERS=0x0100

# Byte positions in AUN traffic
AUN_PTYPE=0
AUN_PORT=1
AUN_CTRL=2
AUN_PAD=3
AUN_SEQ1=4
AUN_SEQ2=5
AUN_SEQ3=6
AUN_SEQ4=7
AUN_DATA=8

AUN_PT_TIMEOUT=0 # Used to signal timeout without receiving ACK, NAK or an immediate reply
AUN_PT_BCAST=1
AUN_PT_DATA=2
AUN_PT_ACK=3
AUN_PT_NAK=4
AUN_PT_IMM=5
AUN_PT_IMMREP=6
# NB: the HPB's "INK" type is not known to AUN and not defined here

FSOP_RESULT_OK=0
FSOP_RESULT_SAVE=1
FSOP_RESULT_LOAD=2
FSOP_RESULT_CAT=3
FSOP_RESULT_INFO=4
FSOP_RESULT_IAM=5
FSOP_RESULT_SDISC=6
FSOP_RESULT_DIR=7
FSOP_RESULT_UNKNOWNCOMMAND=8
FSOP_RESULT_NO_REPLY=-1

# Transmission failures
AUN_TX_RESULT_NOTLISTENING=-1
AUN_TX_RESULT_NOADDRESS=-2
AUN_TX_RESULT_UNKNOWN=-255

class AUNClient:

    def __init__(self, localport = 32768, bind_addr = '', timeout = 1.5, debug_on = False, traffic_debug_on = False, aunmap_file = None, hostmap_file = None):
        self.local_port = localport
        self.handles = { }
        self.aun_timeout = timeout
        self.seq = 0x4000
        self.traffic_debug_enabled = traffic_debug_on
        self.debug_enabled = debug_on
        self.local_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.local_socket.bind((bind_addr, self.local_port))
        self.last_port = 0
        self.ports_mutex = threading.Lock()
        self.ports = { }
        self.port_conditions = { }
        self.aunmap = { }
        self.hostmap = { }

        # Find home

        user_home = os.path.expanduser("~")

        if (aunmap_file == None):
            aunmap_file = f"{user_home}/.aunmap"

        if (hostmap_file == None):
            hostmap_file = f"{user_home}/.hostmap"

        # Load aunmap
        
        if os.path.isfile(aunmap_file):

            with open(aunmap_file, "r") as h:
                for l in h:

                    my_match = re.search("^\s*ADDMap\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(\d{1,3})\s*$", l)

                    if my_match != None:
                        self.aunmap[match.group(2)] = match.group(1)
                    else: 
                        my_match = re.search("^\s*ADDMap\s+(\d{1,3})\.(\d{1,3})\.N\.(\d{1,3})\s+(\d{1,3})\-(\d{1,3})\s*$", l, re.I)
                        if my_match != None:
                            for net in range(int(my_match.group(4)), int(my_match.group(5))):
                                self.aunmap[net] = f"{my_match.group(1)}.{my_match.group(2)}.{net}.{my_match.group(3)}"
    
        # Load AUN hosts

        if os.path.isfile(hostmap_file):

            with open(hostmap_file, "r") as h:
                for l in h:
                    my_match = re.search("(\d{1,3}) (\d{1,3}) (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) (\d{3,5})", l, re.I)
                    if my_match != None:
                        self.hostmap[(match.group(1), match.group(2))] = (match.group(3), match.group(4))

        self.hostmap_inverse = { v:k for k, v in self.hostmap.items() }
        self.aunmap_inverse = { v:k for k, v in self.aunmap.items() }

        self.listener_thread = threading.Thread(target=self.listener_code, args=())
        self.listener_thread.start()

        return None

    def listener_code(self):
        while True:
            data, addr = self.local_socket.recvfrom(32768)
            source_address = addr[0]
            source_port = addr[1]
            #self.debug(f"Received traffic from {source_address}:{source_port} - {data}")
            seq = (data[AUN_SEQ1]) + (data[AUN_SEQ2] << 8) + (data[AUN_SEQ3] << 16) + (data[AUN_SEQ4] << 24)
            packet = bytearray(data)
            packet[AUN_CTRL] |= 0x80
            (net, stn) = self.AUNUnMapAddress(addr)
            if (net == 0): # Dump packet
                traffic = f"--> {self.aun_typestr(packet[AUN_PTYPE]):>5} {packet[AUN_PORT]:02X}:{packet[AUN_CTRL]:02X} Seq {seq:08X}: {packet[8:]} from Unknown Source! ({addr})"
            else:
                traffic = f"--> {self.aun_typestr(packet[AUN_PTYPE]):>5} {packet[AUN_PORT]:02X}:{packet[AUN_CTRL]:02X} Seq {seq:08X}: {packet[8:]} from {net}.{stn} ({addr})"
            self.traffic_debug(traffic)
            if (packet[AUN_PTYPE] == AUN_PT_IMM):
                if (packet[AUN_CTRL] == 0x88): # Machinepeek
                    mp_reply = bytearray([(PEEK_HW & 0xff00) >> 8, ((PEEK_HW & 0xff)), (PEEK_VERS & 0xff00) >> 8, (PEEK_VERS & 0xff)])
                    mp_reply_aun = self.AUNPacket(AUN_PT_IMMREP, 0x00, 0x88, seq, mp_reply)
                    self.AUNTransmit(net, stn, mp_reply_aun)
            elif (packet[AUN_PTYPE] == AUN_PT_DATA): # Data - send ACK - we'll be more particular later!
                if self.ports.get(packet[AUN_PORT]) != None:
                    ack = self.AUNPacket(AUN_PT_ACK, packet[AUN_PORT], packet[AUN_CTRL], seq, bytearray([]))
                    self.AUNTransmit(net, stn, ack)
                    self.ports[packet[AUN_PORT]].append(packet)
                    if self.port_conditions[packet[AUN_PORT]] != None:
                        self.port_conditions[packet[AUN_PORT]].acquire()
                        self.port_conditions[packet[AUN_PORT]].notify()
                        self.port_conditions[packet[AUN_PORT]].release()
                else:
                    nak = self.AUNPacket(AUN_PT_NAK, packet[AUN_PORT], packet[AUN_CTRL], seq, bytearray([]))
                    self.AUNTransmit(net, stn, nak)

    def AUNPacket(self, ptype, port, ctrl, seq, data):
        header = bytearray([ptype, port, ctrl | 0x80, 0x00, (seq & 0xff), (seq & 0xff00) >> 8, (seq & 0xff0000) >> 16, (seq & 0xff000000) >> 24])
        packet = header + data
        return packet
        
    def AUNTransmit(self, net, stn, packet):
        netaddress, netport = self.AUNMapAddress(net, stn)

        if netaddress == None or netport == None:
            return AUN_TX_RESULT_NO_ADDRESS, 0, 0

        self.sent_time = time.time()
        output = f"<-- {self.aun_typestr(packet[AUN_PTYPE]):>5} {packet[AUN_PORT]:02X}:{packet[AUN_CTRL]:02X} Seq {(packet[AUN_SEQ1] + (packet[AUN_SEQ2] << 8) + (packet[AUN_SEQ3] << 16) + (packet[AUN_SEQ4] << 24)):08X}: {packet[8:]} to {net}.{stn} ({netaddress}:{netport})"
        self.traffic_debug(output)
        packet[AUN_CTRL] &= 0x7f # Strip high bit
        self.local_socket.sendto(packet, 0, (netaddress, netport))
        self.seq += 4
        if (packet[AUN_PTYPE] == AUN_PT_IMM):
            # Await IMMREP or timeout
            x=1
            #print ("Would be waiting for IMMREP or timeout")
        elif (packet[AUN_PTYPE] == AUN_PT_DATA):
            # Await ACK or NAK or timeout
            x=1
            #print ("Would be waiting for ACK NAK or timeout")

    def AUNUnMapAddress(self, addr):

        net = stn = None
        netaddress, netport = addr
        econet_addr = self.hostmap_inverse.get((netaddress, netport))

        if econet_addr != None:
            net = econet_addr[0]
            stn = econet_addr[1]

        if (econet_addr == None): # Try AUNmap instead

            # Set last bit of address to 0
            stn_match = re.search("\.(\d{1,3})$", netaddress)

            if stn_match:
                stn = int(stn_match.group(1))

            zero_net = re.sub("\.\d{1,3}$", ".0", netaddress, 1)
            net = self.aunmap_inverse.get(zero_net)

        if (net == None):
            net = 0
            stn = 0

        return net, stn 

    def AUNMapAddress(self, net, stn): # Look up IP address and port to transmit to

        if net == 0:
           net = 128 # Default to net 128

        if net > 254 or net < 1:
            return None, None

        if stn > 254 or stn < 1:
            return None, None

        address = None
        dest_port = None

        if self.hostmap.get((net, stn)):
            (address, dest_port) = self.hostmap.get((net, stn))

        if address == None:
            address = self.aunmap.get(net)
            if address != None:
                address = re.sub("\.0$", f".{stn}", address, 1)
                dest_port = 32768

        return address, dest_port

    def FSOp(self, net, stn, OpNumber, data):

        self.ReplyPort = self.DataPort()

        handle_urd = handle_cwd = handle_lib = 0

        if self.handles.get((net, stn)):
            handle_urd = self.handles[(net, stn)][0]
            handle_cwd = self.handles[(net, stn)][1]
            handle_lib = self.handles[(net, stn)][2]

        self.op_data = bytearray([self.ReplyPort, OpNumber, handle_urd, handle_cwd, handle_lib]) + data
    
        self.port_conditions[self.ReplyPort].acquire()

        packet = self.AUNPacket(AUN_PT_DATA, 0x99, 0x80, self.seq, self.op_data)
        self.AUNTransmit(net, stn, packet)
 
        result_code = FSOP_RESULT_NO_REPLY
        error_code = 0xff

        if self.port_conditions[self.ReplyPort].wait(1.5): # Returns True if no timeout

            if (len(self.ports[self.ReplyPort]) > 0):

                self.packet = self.ports[self.ReplyPort].pop() # Should be None if nothing there
                result_code = self.packet[AUN_DATA]
                error_code = self.packet[AUN_DATA+1]

                if error_code != 0:
                    error_string = self.packet[AUN_DATA+2:].decode('ascii')
                    print (f"Error &{error_code:02X}: {error_string}")
                elif (result_code == FSOP_RESULT_LOAD):
                    print ("Server has decoded that request as a *LOAD")
                elif (result_code == FSOP_RESULT_SAVE):
                    print ("Server has decoded that request as a *SAVE")
                elif (result_code == FSOP_RESULT_CAT):
                    print ("Server invites you to do a catalogue")
                elif (result_code == FSOP_RESULT_INFO):
                    
                    #strip_match = re.search("^(.+)\r\x80$", self.packet[AUN_DATA+2])
                    #if (strip_match):
                        #print (strip_match.group(1))
                    #else:
                        print ("Server has decoded that request as a *INFO, but result not understood")
                elif (result_code == FSOP_RESULT_IAM): # Logged in
                    urd_handle = self.packet[AUN_DATA+2]
                    cwd_handle = self.packet[AUN_DATA+3]
                    lib_handle = self.packet[AUN_DATA+4]
                    self.handles[(net, stn)] = (urd_handle, cwd_handle, lib_handle)
                    self.debug (f"Logged in to {net}.{stn} with URD = {urd_handle:02X}, CWD = {cwd_handle:02X}, LIB = {lib_handle:02X}")
                elif (result_code == FSOP_RESULT_SDISC):
                    print ("Server has decoded that request as a *SDISC")
                elif (result_code == FSOP_RESULT_DIR): # Dir handle change
                    current_handles = self.handles[(net, stn)]
                    self.handles[(net, stn)] = (current_handles[0], self.packet[AUN_DATA+2], current_handles[2])
                    self.debug (f"Changed working directory on {net}.{stn}, new URD handle = {self.packet[AUN_DATA+2]:02X}")
                elif (result_code == FSOP_RESULT_UNKNOWNCOMMAND):
                    self.debug ("Unknown command within fileserver and cannot run programmes in this environment")
        else:
           self.packet = None
   
           self.port_conditions[self.ReplyPort].release()
   
           self.put_port(self.ReplyPort)

        return result_code, error_code, self.packet

    def DataPort(self):
    
        self.ports_mutex.acquire()
    
        self.port=self.last_port + 1
    
        while (1):
            if self.port in self.ports:
                self.port = self.port + 1
                if self.port == 0:
                    self.port = 1
                if (self.port == self.last_port):
                    self.debug ("No available ports!")
                    self.ports_mutex.release()
                    return 0
            else:
                self.ports[self.port] = [ ]
                self.port_conditions[self.port] = threading.Condition()
                self.last_port = self.port
                self.ports_mutex.release()
                return self.port
     
    def put_port(self, port):
        
        self.ports_mutex.acquire()
        self.ports.pop(port)
        self.port_conditions.pop(port)
        self.ports_mutex.release()
    
    
    def aun_typestr(self, p):

        if p == AUN_PT_BCAST:
            return "Bcast"
        elif p == AUN_PT_DATA:
            return "Data"
        elif p == AUN_PT_ACK:
            return "ACK"
        elif p == AUN_PT_NAK:
            return "NAK"
        elif p == AUN_PT_IMM:
            return "ImmRQ"
        elif p == AUN_PT_IMMREP:
            return "ImmRP"
        else:
            return "Unk."

    def traffic_debug (self, info):
        if self.traffic_debug_enabled:
            print(info)

    def debug (self, info):
        if self.debug_enabled:
            print(info)


