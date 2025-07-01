import requests
import socket
import threading
import argparse
import time

parser = argparse.ArgumentParser(description='Websocket and TCP server address options.')

parser.add_argument('-W', '--webstream', type=str, dest="webstream", help='address of the MPEG-TS stream for processing')
parser.add_argument('-I', '--server-ip', type=str, dest="host", default='192.168.0.65', help='IP address for the forwarding TCP server')
parser.add_argument('-P', '--server-port', type=int, dest="port", default=4001, help='port for the forwarding TCP server')
parser.add_argument('-D', '--data-pid', type=int, dest="pid", default=101, help='PID in the MPEG-TS webstream containing the UECP data')
parser.add_argument('-B', '--buffer-rt', dest="buffer", action='store_true', help='Simulate buffer config settings for UECP RT')
parser.add_argument('-A', '--uecp-addr', type=int, dest="addr", default=0, help='UECP address for wanted RT packets, this should be set to avoid unexpected behaviour when using buffer simulation')

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
        
def remove_padding(byte_array):
    """
    Returns the part of the byte array after the last instance of two consecutive 0xFF bytes.

    Args:
        byte_array (bytearray): The input byte array.

    Returns:
        bytearray: The part of the byte array after the last 0xFF pair.
    """
    # Reverse the byte array to find the last instance from the original end
    reversed_byte_array = byte_array[::-1]
    # Find the index of the last occurrence of two consecutive 0xFF bytes
    index = next((i for i in range(len(reversed_byte_array) - 1) if reversed_byte_array[i] == 0xFF and reversed_byte_array[i + 1] == 0xFF), None)

    if index is not None:
        # Return the part of the byte array after the last 0xFF pair
        return reversed_byte_array[:index][::-1]
    else:
        # If there are no instances of two consecutive 0xFF bytes, return the original array
        return byte_array

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

def find_subarray_position(main_byte_array, sub_byte_array):
    try:
        position = main_byte_array.index(sub_byte_array)
        return position
    except ValueError:
        return None  # Subarray not found in the main array

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
    pkt = unescape_uecp(data)
    if args.buffer and pkt[5] == 0x0A and (pkt[2] == args.addr):
        buffer_conf = pkt[9]
        if not buffer_conf & 0x40:
            # If bit 6 is not set, we need to clear the RT buffer and trigger to send
            rt_buffer = []
            rt_index = 0
            rt_last_sent = 0
        # Append this message to the end of the buffer
        rt_buffer.append(data)
    else:
        send_packet_to_server(data)


pid = int(args.pid)
print(f"Decoding UECP data from PID {pid}...")

#Connect to Stereo Tool UECP server
sock = connect_to_server()

try:
    response = requests.get(args.webstream, stream=True)

    if response.status_code == 200:
        while True:
            if args.buffer and len(rt_buffer) > 0 and time.time()-rt_last_sent >= 15:
                if (rt_index >= len(rt_buffer) > 1) or (rt_index < len(rt_buffer)):
                    if rt_index >= len(rt_buffer):
                        rt_index = 0
                    send_packet_to_server(rt_buffer[rt_index])
                    rt_index += 1
                    rt_last_sent = time.time()
            pkt = response.raw.read(188)
            if len(pkt) == 0 :
                break
            pktpid = ((pkt[1] & 0x1f) << 8) | pkt[2]
            if pktpid == pid :
                #Process if PID matches
                if (pkt[3] & 0x30) < 0x30 :
                    pkt = pkt[6:]
                else :
                    pkt = pkt[pkt[4]+5:]

                uecp_data = remove_padding(pkt)
                #Fix issue with strange separator in some data.
                msg_trim_index = find_subarray_position(uecp_data, b'\xFF\xEB\x07')
                if msg_trim_index != None :
                    uecp_data = uecp_data[msg_trim_index+3:]

                if uecp_data :
                    uecp_msgs = split_uecp_msgs(uecp_data)
                    for msg in uecp_msgs :
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
    else:
        print(f'Failed to connect to the stream. Status code: {response.status_code}')
        sock.close()
except KeyboardInterrupt:
    print('Stopping...')
    sock.close()
except Exception as e:
    print(f"Error: {e}")