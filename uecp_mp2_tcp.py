import requests
import socket
import threading
import argparse
import time
import av

parser = argparse.ArgumentParser(description='Websocket and TCP server address options.')

parser.add_argument('-W', '--webstream', type=str, dest="webstream", help='address of the MP2 stream containing UECP ancillary data')
parser.add_argument('-I', '--server-ip', type=str, dest="host", default='192.168.0.65', help='IP address for the forwarding TCP server')
parser.add_argument('-P', '--server-port', type=int, dest="port", default=4001, help='port for the forwarding TCP server')
parser.add_argument('-B', '--buffer-rt', dest="buffer", action='store_true', help='Simulate buffer config settings for UECP RT')

args = parser.parse_args()

rt_buffer = []
rt_last_sent = 0
rt_index = 0

uecp_tmp = bytearray()

def connect_to_server() :
    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Connect the socket to the server's address
    server_address = (args.host, args.port)
    print(f'Connecting to {args.host} port {args.port}')
    sock.connect(server_address)
    return sock

def send_packet_to_server(data):
    global sock
    try:
        # Send data
        print(f'Sending data: {data}')
        sock.sendall(data)
    except Exception as e:
        print(f'An error occurred: {e}')
        if isinstance(e, ConnectionResetError) or getattr(e, 'winerror', None) == 10054 or getattr(e, 'winerror', None) == 10038:
            print('Trying to reconnect to UECP server...')
            try:
                sock.close()
            except Exception:
                pass
            try:
                sock = connect_to_server()
                sock.sendall(data)
            except Exception as e:
                print(f'Reconnect failed: {e}')

def split_uecp_msgs(byte_array):
    """
    Splits a byte array into a list of byte arrays by the character 0xFF,
    preserving the terminating 0xFF byte in each split array.

    Args:
        byte_array (bytearray): The input byte array.

    Returns:
        list: A list of byte arrays split by the character 0xFF.
    """
    split_arrays = []
    current_array = bytearray()

    for byte in byte_array:
        current_array.append(byte)
        if byte == 0xFF:
            # Add the current array to the list and start a new one
            split_arrays.append(current_array)
            current_array = bytearray()

    # Add the last array (if not empty) to the list
    if current_array:
        split_arrays.append(current_array)

    return split_arrays

def unescape_uecp(byte_array) :
    next_escaped = False
    escaped_array = bytearray()
    for b in byte_array :
        if next_escaped :
            next_escaped = False
            if b+0xFD <= 0xFF :
                escaped_array.append(b+0xFD)
            else :
                escaped_array.append(0xFF)
        elif b == 0xFD :
            next_escaped = True
        else :
            escaped_array.append(b)
    return escaped_array

def process_packet(data):
    global rt_buffer
    global rt_last_sent
    global rt_index
    pkts = split_uecp_msgs(data)
    for pkt in pkts:
        pkt_uesc = unescape_uecp(pkt)
        if args.buffer and pkt_uesc[5] == 0x0A:
            buffer_conf = pkt_uesc[9]
            if not buffer_conf & 0x40:
                # If bit 6 is not set, we need to clear the RT buffer and trigger to send
                rt_buffer = []
                rt_index = 0
                rt_last_sent = 0
            # Append this message to the end of the buffer
            rt_buffer.append(pkt)
            # Now get the message
        else:
            send_packet_to_server(pkt)

#Read first MPEG audio packet header to work out length and sync to frames
mp2_br = [0,32,48,56,64,80,96,112,128,160,192,224,256,320,384]
mp2_sr = [44100,48000,32000]
first_frame = True

#Connect to Stereo Tool UECP server
sock = connect_to_server()

try:
    # Open the webstream containing audio information
    container = av.open(args.webstream)
    # Identify audio stream (e.g., MPEG-1 Layer II)
    audio_stream = next(s for s in container.streams if s.type == 'audio')

    for packet in container.demux(audio_stream):
        if packet.dts is None:
            continue  # skip empty packets
        pkt = bytes(packet)
        if first_frame:
            if pkt[0] == 0xFF and (pkt[1] == 0xFD or pkt[1] == 0xFC) :
                print("This is MPEG 1 Layer 2 Audio!")
                br_index = (pkt[2] >> 4) & 0xF
                sr_index = (pkt[2] >> 2) & 0x3
                print("Bitrate: " + str(mp2_br[br_index]) + "kbps Sample Rate: " + str(mp2_sr[sr_index]) + "Hz")
                first_frame = False
            else :
                print("Not valid MPEG audio data!\n")
                exit()
        pkt_rev = pkt[::-1]
        anc_header = pkt_rev[0]
        msg = None

        if anc_header == 0xFD :
            anc_len = pkt_rev[1]
            if anc_len > 0:
                msg = pkt_rev[2:2+anc_len]
        elif anc_header != 0x00 :
            anc_len = pkt_rev[0]
            if anc_len > 0:
                msg = pkt_rev[1:1+anc_len]

        if msg :
            if msg[0] == 0xFE :
                #This is a new message, we can't process any fragments.
                uecp_tmp = bytearray()
                if msg[-1] == 0xFF :
                    #This is a full message, process it.
                    process_packet(msg)
                else :
                    #Otherwise this is a partial message so put it in the buffer.
                    uecp_tmp = msg
            else :
                #This is a fragment, if we have a buffer we need to add it
                if uecp_tmp :
                    uecp_tmp = uecp_tmp + msg
                    if uecp_tmp[-1] == 0xFF :
                        msg = uecp_tmp
                        #This is a full message, process it and empty the buffer
                        process_packet(msg)
                        uecp_tmp = bytearray()
except KeyboardInterrupt:
    print('Stopping...')
    sock.close()
except Exception as e:
    print(f"Error: {e}")