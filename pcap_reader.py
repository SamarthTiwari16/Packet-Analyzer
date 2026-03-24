import struct
from dataclasses import dataclass

@dataclass
class PcapGlobalHeader:
    magic_number: int
    version_major: int
    version_minor: int
    thiszone: int
    sigfigs: int
    snaplen: int
    network: int

@dataclass
class PcapPacketHeader:
    ts_sec: int
    ts_usec: int
    incl_len: int
    orig_len: int

class PcapReader:
    def __init__(self):
        self.file = None
        self.global_header = None
        self.needs_byte_swap = False
        self.byte_order = "<" # Default Little Endian

    def open(self, filename: str) -> bool:
        try:
            self.file = open(filename, "rb")
        except IOError:
            return False

        global_hdr_data = self.file.read(24)
        if len(global_hdr_data) < 24:
            return False

        # Magic number determines endianness
        magic_num = struct.unpack("<I", global_hdr_data[:4])[0]
        if magic_num == 0xa1b2c3d4 or magic_num == 0xa1b23c4d:
            self.byte_order = "<"
            self.needs_byte_swap = False
        elif magic_num == 0xd4c3b2a1 or magic_num == 0x4d3cb2a1:
            self.byte_order = ">"
            self.needs_byte_swap = True
        else:
            print("Not a valid PCAP file or unsupported format.")
            return False

        fmt = self.byte_order + "IHHIIII"
        unpacked = struct.unpack(fmt, global_hdr_data)
        
        self.global_header = PcapGlobalHeader(
            magic_number=unpacked[0],
            version_major=unpacked[1],
            version_minor=unpacked[2],
            thiszone=unpacked[3],
            sigfigs=unpacked[4],
            snaplen=unpacked[5],
            network=unpacked[6]
        )

        return True

    def close(self):
        if self.file:
            self.file.close()

    def read_next_packet(self):
        """
        Returns a tuple of (PcapPacketHeader, bytes) representing the raw packet, 
        or (None, None) if EOF or error.
        """
        if not self.file:
            return None, None

        hdr_data = self.file.read(16)
        if len(hdr_data) < 16:
            return None, None

        fmt = self.byte_order + "IIII"
        unpacked = struct.unpack(fmt, hdr_data)

        header = PcapPacketHeader(
            ts_sec=unpacked[0],
            ts_usec=unpacked[1],
            incl_len=unpacked[2],
            orig_len=unpacked[3]
        )

        # Truncated or corrupted length check
        if header.incl_len == 0 or header.incl_len > 65535:
            # Usually incl_len should be reasonable, max snaplen is typically 65535
            pass

        packet_data = self.file.read(header.incl_len)
        if len(packet_data) < header.incl_len:
            # Reached EOF before full length or corrupted file
            return None, None

        return header, packet_data
