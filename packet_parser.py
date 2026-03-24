import struct
from dataclasses import dataclass
import socket

class TCPFlags:
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20

class Protocol:
    ICMP = 1
    TCP = 6
    UDP = 17

@dataclass
class ParsedPacket:
    has_ip: bool = False
    ip_version: int = 0
    src_ip: str = ""
    dest_ip: str = ""
    protocol: int = 0
    
    has_tcp: bool = False
    has_udp: bool = False
    src_port: int = 0
    dest_port: int = 0
    
    tcp_flags: int = 0
    
    payload_length: int = 0
    payload_offset: int = 0

class PacketParser:
    @staticmethod
    def parse(packet_data: bytes) -> ParsedPacket:
        """
        Parses raw packet data starting from the Ethernet layer.
        Returns a ParsedPacket object with the extracted information.
        """
        parsed = ParsedPacket()
        data_len = len(packet_data)
        offset = 0

        # --- Parse Ethernet (14 bytes) ---
        if data_len < 14:
            return parsed
        
        # dest_mac (6), src_mac (6), eth_type (2)
        eth_type = struct.unpack("!H", packet_data[12:14])[0]
        offset += 14

        # Check if IPv4 (0x0800)
        if eth_type != 0x0800:
            return parsed

        # --- Parse IPv4 ---
        if offset + 20 > data_len:
            return parsed

        version_ihl = packet_data[offset]
        version = version_ihl >> 4
        ihl = version_ihl & 0x0F
        ip_header_length = ihl * 4

        if version != 4:
            return parsed

        if offset + ip_header_length > data_len:
            return parsed

        parsed.has_ip = True
        parsed.ip_version = 4
        
        parsed.protocol = packet_data[offset + 9]
        
        src_ip_bytes = packet_data[offset + 12:offset + 16]
        dst_ip_bytes = packet_data[offset + 16:offset + 20]
        
        parsed.src_ip = socket.inet_ntoa(src_ip_bytes)
        parsed.dest_ip = socket.inet_ntoa(dst_ip_bytes)

        offset += ip_header_length

        # --- Parse Transport Layer ---
        if parsed.protocol == Protocol.TCP:
            if offset + 20 > data_len:
                return parsed

            parsed.has_tcp = True
            
            src_port, dest_port = struct.unpack("!HH", packet_data[offset:offset + 4])
            parsed.src_port = src_port
            parsed.dest_port = dest_port

            data_offset_flags = struct.unpack("!H", packet_data[offset + 12:offset + 14])[0]
            tcp_header_length = ((data_offset_flags >> 12) & 0x0F) * 4
            parsed.tcp_flags = data_offset_flags & 0x01FF # taking all flags

            offset += tcp_header_length

        elif parsed.protocol == Protocol.UDP:
            if offset + 8 > data_len:
                return parsed

            parsed.has_udp = True
            
            src_port, dest_port = struct.unpack("!HH", packet_data[offset:offset + 4])
            parsed.src_port = src_port
            parsed.dest_port = dest_port

            offset += 8

        else:
            # Other protocols not parsed
            return parsed

        # Calculate payload
        if offset < data_len:
            parsed.payload_offset = offset
            parsed.payload_length = data_len - offset
        
        return parsed
