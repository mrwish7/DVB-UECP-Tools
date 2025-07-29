import sys
import requests
import socket
import argparse

sqc = 1
buffer = bytearray()
START_MARKER = b'\x20\x20\x30'
END_MARKER = b'\x0a\x0d\x01'

parser = argparse.ArgumentParser(description='Websocket and TCP server address options.')

parser.add_argument('-W', '--webstream', type=str, dest="webstream", help='address of the MPEG-TS stream for processing')
parser.add_argument('-I', '--server-ip', type=str, dest="host", default='192.168.0.65', help='IP address for the forwarding TCP server')
parser.add_argument('-P', '--server-port', type=int, dest="port", default=4001, help='port for the forwarding TCP server')
parser.add_argument('-D', '--data-pid', type=int, dest="pid", default=101, help='PID in the MPEG-TS webstream containing the RDS data')

args = parser.parse_args()

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

# Function to generate 2-byte UECP CRC
def crc16_ccitt(data: bytes, poly=0x1021, init_crc=0xFFFF) -> bytes:
    crc = init_crc
    for byte in data:
        crc ^= (byte << 8)
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1) ^ poly
            else:
                crc <<= 1
            crc &= 0xFFFF  # Ensure it's a 16-bit value
    crc = 0xFFFF - crc # Invert CRC by subtracting from 0xFFFF
    return crc.to_bytes(2, byteorder='big')

def uecp_escape_bytes(data: bytearray) -> bytearray:
    ESCAPE = 0xFD
    replacements = {
        0xFD: bytearray([ESCAPE, 0x00]),
        0xFE: bytearray([ESCAPE, 0x01]),
        0xFF: bytearray([ESCAPE, 0x02])
    }

    escaped = bytearray()
    for byte in data:
        if byte in replacements:
            escaped.extend(replacements[byte])
        else:
            escaped.append(byte)
    return escaped

def create_uecp_rt(rt: bytearray):
    global sqc
    pktlen = len(rt)+5
    uecp_pkt = bytearray([0x00, 0x00, sqc, pktlen, 0x0A, 0x00, 0x00, pktlen-4, 0x0B])
    uecp_pkt = uecp_pkt + rt
    crc = crc16_ccitt(uecp_pkt)
    uecp_pkt = uecp_pkt + crc
    uecp_pkt = uecp_escape_bytes(uecp_pkt)
    if (sqc == 255):
        sqc = 1
    else:
        sqc = sqc + 1
    return bytearray([0xFE]) + uecp_pkt + bytearray([0xFF])

pid = int(args.pid)
print(f"Getting RDS data from PID {pid}...")

#Connect to Stereo Tool UECP server
sock = connect_to_server()

try:
    response = requests.get(args.webstream, stream=True)

    if response.status_code == 200:
        while True:
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

                if (len(pkt) > 0):
                    buffer.extend(pkt)
                    while True:
                        start_index = buffer.find(START_MARKER)
                        if start_index == -1:
                            break  # No start found yet

                        end_index = buffer.find(END_MARKER, start_index + len(START_MARKER))
                        if end_index == -1:
                            break  # Wait for more data

                        data_segment = buffer[start_index + len(START_MARKER) : end_index]
                        uecp = create_uecp_rt(data_segment)
                        send_packet_to_server(uecp)

                        # Remove processed data from buffer
                        buffer = buffer[end_index + len(END_MARKER):]
    else:
        print(f'Failed to connect to the stream. Status code: {response.status_code}')
        sock.close()
except KeyboardInterrupt:
    print('Stopping...')
    sock.close()
except Exception as e:
    print(f"Error: {e}")
