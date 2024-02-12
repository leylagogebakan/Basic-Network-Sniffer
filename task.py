from scapy.all import sniff, Ether
import struct

def main():
    sniff(prn=process_packet, store=0)

def process_packet(packet):
    if packet.haslayer(Ether):
        dest_mac = packet[Ether].dst
        src_mac = packet[Ether].src
        eth_proto = packet[Ether].type
        data = packet[Ether].payload
        print('\nEthernet Frame:')
        print('Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))

        if eth_proto == 8:
            (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
            print('\tIPv4 Packet:')
            print('\t\tVersion: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
            print('\t\tProtocol: {}, Source: {}, Target: {}'.format(proto, src, target))

            if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print('\t\tICMP Packet:')
                print('\t\t\tType: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))

            elif proto == 6:
                src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_segment(data)
                print('\t\tTCP Segment:')
                print('\t\t\tSource Port: {}, Destination Port: {}'.format(src_port, dest_port))
                print('\t\t\tSequence: {}, Acknowledgment: {}'.format(sequence, acknowledgement))
                print('\t\t\tFlags:')
                print('\t\t\t\tURG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))

            elif proto == 17:
                src_port, dest_port, length, data = udp_segment(data)
                print('\t\tUDP Segment:')
                print('\t\t\tSource Port: {}, Destination Port: {}, Length: {}'.format(src_port, dest_port, length))

def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

def ipv4(addr):
    return '.'.join(map(str, addr))

def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

def tcp_segment(data):
    src_port, dest_port, sequence, acknowledgement, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

def udp_segment(data):
    src_port, dest_port, length = struct.unpack('! H H H', data[:6])
    return src_port, dest_port, length, data[8:]

main()
