import argparse
import requests
from datetime import datetime

ebu_chars = ['á', 'à', 'é', 'è', 'í', 'ì', 'ó', 'ò', 'ú', 'ù', 'Ñ', 'Ç', 'Ş', 'ß', '¡', 'Ĳ',
			 'â', 'ä', 'ê', 'ë', 'î', 'ï', 'ô', 'ö', 'û', 'ü', 'ñ', 'ç', 'ş', 'ğ', 'ı', 'ĳ',
			 'ª', 'α', '©', '‰', 'Ğ', 'ě', 'ň', 'ő', 'π', '€', '£', '$', '←', '↑', '→', '↓',
			 '⁰', '¹', '²', '³', '±', 'İ', 'ń', 'ű', 'μ', '¿', '÷', '°', '¼', '½', '¾', '§',
			 'Á', 'À', 'É', 'È', 'Í', 'Ì', 'Ó', 'Ò', 'Ú', 'Ù', 'Ř', 'Č', 'Š', 'Ž', 'Đ', 'L',
			 'Â', 'Ä', 'Ê', 'Ë', 'Î', 'Ï', 'Ô', 'Ö', 'Û', 'Ü', 'ř', 'č', 'š', 'ž', 'đ', 'l',
			 'Ã', 'Å', 'Æ', 'Œ', 'ŷ', 'Ý', 'Õ', 'Ø', 'Þ', 'Ŋ', 'Ŕ', 'Ć', 'Ś', 'Ź', 'Ŧ', 'ð',
			 'ã', 'å', 'æ', 'œ', 'ŵ', 'ý', 'õ', 'ø', 'þ', 'ŋ', 'ŕ', 'ć', 'ś', 'ź', 'ŧ', 'ÿ' ]

ptys = ["None","News","Current affairs","Information","Sport","Education","Drama","Culture",
        "Science","Varied","Pop music","Rock music","Easy listening","Light classical",
        "Serious classical","Other music","Weather","Finance","Children's programmes",
        "Social affairs","Religion","Phone-in","Travel","Leisure","Jazz music","Country music",
        "National music","Oldies music","Folk music","Documentary","Alarm test","Alarm"]

parser = argparse.ArgumentParser(description='MPEG-TS stream and data PID address options.')

parser.add_argument('-W', '--webstream', type=str, dest="webstream", help='address of the MPEG-TS stream for processing')
parser.add_argument('-D', '--data-pid', type=int, dest="pid", default=101, help='PID in the MPEG-TS webstream containing the UECP data')

args = parser.parse_args()
pid = args.pid

print(f"Decoding UECP data from PID {pid}...")
uecp_tmp = bytearray()

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

def count_uecp_length(byte_array):
    """
    Counts the length of a byte array excluding occurrences of 0xFD.

    Args:
        byte_array (bytearray): The input byte array.

    Returns:
        int: The length of the byte array after excluding 0xFD occurrences.
    """
    filtered_array = bytearray(filter(lambda x: x != 0xFD, byte_array))
    return len(filtered_array)

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

def process_uecp(byte_array) :
    global ebu_chars
    #Process the UECP packet
    time = datetime.now()
    uecp = unescape_uecp(byte_array)
    addr = (uecp[1] << 8) | uecp[2]
    addr_site = (addr >> 6) & 0x3FF
    addr_enc = addr & 0x3F
    sqc = uecp[3]
    mec = uecp[5]
    if mec == 0x01 :
        mec_desc = "PI"
        pi = uecp[8:-3]
        text = pi[0:2].hex().upper()
        print(f"{time.strftime('%H:%M:%S')} | {addr_site:4}/{addr_enc:2} | {'{:02X}'.format(mec)} [{mec_desc}] | {text}")
    elif mec == 0x02 :
        mec_desc = "PS"
        text = ""
        for c in uecp[8:8+8] :
            text += chr(c)
        print(f"{time.strftime('%H:%M:%S')} | {addr_site:4}/{addr_enc:2} | {'{:02X}'.format(mec)} [{mec_desc}] | {text}")
    elif mec == 0x03 :
        mec_desc = "TA"
        ta = "ON" if uecp[8] & 0x1 else "OFF"
        tp = "ON" if uecp[8] & 0x2 else "OFF"
        text = f"TP: {tp} TA: {ta}"
        print(f"{time.strftime('%H:%M:%S')} | {addr_site:4}/{addr_enc:2} | SQC: {sqc} | {'{:02X}'.format(mec)} [{mec_desc}] | {text}")
    elif mec == 0x04 :
        mec_desc = "DI"
        ms = "stereo" if uecp[8] & 0x1 else "mono"
        ah = "Y" if uecp[8] & 0x2 else "N"
        cmp = "Y" if uecp[8] & 0x4 else "N"
        dpty = "Y" if uecp[8] & 0x8 else "N"
        text = f"Mod: {ms} Art.Head: {ah} Compressed: {cmp} Dyn.PTY: {dpty}"
        print(f"{time.strftime('%H:%M:%S')} | {addr_site:4}/{addr_enc:2} | SQC: {sqc} | {'{:02X}'.format(mec)} [{mec_desc}] | {text}")
    elif mec == 0x05 :
        mec_desc = "MS"
        ms = "M" if uecp[8] & 0x1 else "S"
        print(f"{time.strftime('%H:%M:%S')} | {addr_site:4}/{addr_enc:2} | SQC: {sqc} | {'{:02X}'.format(mec)} [{mec_desc}] | {ms}")
    elif mec == 0x07 :
        mec_desc = "PTY"
        text = ptys[uecp[8]]
        print(f"{time.strftime('%H:%M:%S')} | {addr_site:4}/{addr_enc:2} | SQC: {sqc} | {'{:02X}'.format(mec)} [{mec_desc}] | {uecp[8]} | {text}")
    elif mec == 0x0A :
        mec_desc = "RT"
        text = ""
        psn = uecp[7]
        dsn = uecp[6]
        conf = uecp[9]
        for c in uecp[10:-3] :
            if c > 0x7F :
                text += ebu_chars[c-0x80]
            else :
                text += chr(c)
        print(f"{time.strftime('%H:%M:%S')} | {addr_site:4}/{addr_enc:2} | SQC: {sqc} | {'{:02X}'.format(mec)} [{mec_desc}] | DSN: {dsn} PSN: {psn} BUF: {'{:02X}'.format(conf)} | {text}")
    elif mec == 0x0D :
        mec_desc = "CT"
        sign = "-" if uecp[13] & 0x20 else "+"
        offset = (uecp[13] & 0x1F)*0.5
        text = f"{'{:02d}'.format(uecp[8])}/{'{:02d}'.format(uecp[7])}/{'{:02d}'.format(uecp[6])} {'{:02d}'.format(uecp[9])}:{'{:02d}'.format(uecp[10])}:{'{:02d}'.format(uecp[11])}.{'{:02d}'.format(uecp[12])} ({sign}{offset})"
        print(f"{time.strftime('%H:%M:%S')} | {addr_site:4}/{addr_enc:2} | SQC: {sqc} | {'{:02X}'.format(mec)} [{mec_desc}] | {text}")
    elif mec == 0x2D :
        mec_desc = "OS"
        man_code = uecp[7:9].decode("utf-8")
        text = ""
        for c in uecp[9:-3] :
            text += chr(c)
        print(f"{time.strftime('%H:%M:%S')} | {addr_site:4}/{addr_enc:2} | SQC: {sqc} | {'{:02X}'.format(mec)} [{mec_desc}] | [{man_code}] | {text}")
    elif mec == 0x1C :
        mec_desc = "DSN"
        text = uecp[6]
        print(f"{time.strftime('%H:%M:%S')} | {addr_site:4}/{addr_enc:2} | {'{:02X}'.format(mec)} [{mec_desc}] | {'{:02X}'.format(text)}")
    elif mec == 0x19 :
        mec_desc = "CT"
        if uecp[6] :
            text = "CT Enabled"
        else:
            text = "CT Disabled"
        print(f"{time.strftime('%H:%M:%S')} | {addr_site:4}/{addr_enc:2} | SQC: {sqc} | {'{:02X}'.format(mec)} [{mec_desc}] | {text}")
    elif mec == 0x24 :
        mec_desc = "FF"
        print(f"{time.strftime('%H:%M:%S')} | {addr_site:4}/{addr_enc:2} | {'{:02X}'.format(mec)} [{mec_desc}]")
    else :
        print(f"{time.strftime('%H:%M:%S')} | {addr_site:4}/{addr_enc:2} | SQC: {sqc} | {'{:02X}'.format(mec)} [??]")

#Main logic
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
                                process_uecp(msg)
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
                                    process_uecp(msg)
                                    uecp_tmp = bytearray()
    else:
        print(f'Failed to connect to the stream. Status code: {response.status_code}')
        sock.close()
except KeyboardInterrupt:
    print('Stopping...')
except Exception as e:
    print(f"Error: {e}")