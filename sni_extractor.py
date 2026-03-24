import struct

class SNIExtractor:
    @staticmethod
    def extract(payload: bytes) -> str:
        """
        Extracts the Server Name Indication (SNI) string from a TLS Client Hello payload.
        Returns the SNI string, or None if not found or invalid format.
        """
        if len(payload) < 43:
            return None
        
        # Check TLS record header:
        # Byte 0: Content Type = 0x16 (Handshake)
        if payload[0] != 0x16:
            return None
        
        # Check Handshake Type:
        # Byte 5: Handshake Type = 0x01 (Client Hello)
        if payload[5] != 0x01:
            return None

        offset = 43  # Skip to session ID length

        # 1. Skip Session ID
        if offset >= len(payload): return None
        session_len = payload[offset]
        offset += 1 + session_len

        # 2. Skip Cipher Suites
        if offset + 2 > len(payload): return None
        cipher_len = struct.unpack("!H", payload[offset:offset+2])[0]
        offset += 2 + cipher_len

        # 3. Skip Compression Methods
        if offset + 1 > len(payload): return None
        comp_len = payload[offset]
        offset += 1 + comp_len

        # 4. Read Extensions Length
        if offset + 2 > len(payload): return None
        ext_len = struct.unpack("!H", payload[offset:offset+2])[0]
        offset += 2

        ext_end = min(offset + ext_len, len(payload))

        # 5. Search for SNI extension (Type 0x0000)
        while offset + 4 <= ext_end:
            ext_type, ext_data_len = struct.unpack("!HH", payload[offset:offset+4])
            offset += 4

            if ext_type == 0x0000:
                # SNI Extension found
                if offset + 5 <= ext_end:
                    # SNI List Length (2) + SNI Type (1) + SNI Length (2)
                    sni_len = struct.unpack("!H", payload[offset+3:offset+5])[0]
                    if offset + 5 + sni_len <= ext_end:
                        try:
                            return payload[offset+5:offset+5+sni_len].decode('utf-8', errors='ignore')
                        except Exception:
                            return None
            
            offset += ext_data_len

        return None


class HTTPHostExtractor:
    @staticmethod
    def extract(payload: bytes) -> str:
        """
        Extracts the Host header domain from an HTTP request.
        """
        try:
            # Quick search for Host header
            idx = payload.find(b"\r\nHost: ")
            if idx == -1:
                # Check if it's the first header
                idx = payload.find(b"Host: ")
                if idx == -1:
                    return None
                offset = idx + 6
            else:
                offset = idx + 8
                
            end_idx = payload.find(b"\r\n", offset)
            if end_idx != -1:
                return payload[offset:end_idx].decode('utf-8', errors='ignore').strip()
        except Exception:
            pass
        return None
