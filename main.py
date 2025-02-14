import socket
import struct
import sys
import json
import time
import re

try:
    import dns.resolver  # type: ignore # Optional: for SRV record resolution.
except ImportError:
    dns = None


class MinecraftServer:
    """
    A unified Python class that implements both the UDP Query and TCP Ping protocols
    for querying a Minecraft server’s status. (Based on the PHP-Minecraft-Query project by xPaw.)
    """
    def __init__(self, host, port=25565, timeout=2, resolve_srv=True):
        """
        Initialize with the server address, port, timeout (seconds) and whether to
        attempt SRV resolution.
        """
        self.host = host
        self.port = int(port)
        self.timeout = float(timeout)
        self.query_players = []  # Filled in by UDP query
        # Optionally resolve SRV record if enabled:
        if resolve_srv:
            self._resolve_srv()


    def _resolve_srv(self):
        """Resolve _minecraft._tcp hostname if possible."""
        # If the host is already an IP address, do nothing.
        try:
            socket.inet_aton(self.host)
            return
        except socket.error:
            pass

        if dns:
            try:
                answers = dns.resolver.resolve('_minecraft._tcp.' + self.host, 'SRV')
                # Use the first returned SRV record.
                for rdata in answers:
                    # The target ends with a dot sometimes.
                    self.host = str(rdata.target).rstrip('.')
                    self.port = rdata.port
                    break
            except Exception:
                pass


    # ────────────────────────────── TCP (Ping) Methods ──────────────────────────────

    def ping_tcp(self):
        """
        Connects via TCP and sends a status request (modern 1.7+ handshake).
        Returns a dict decoded from the server’s JSON reply.
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect((self.host, self.port))

        # Build the handshake packet.
        # Packet structure:
        #   VarInt(packet length) + [PacketID (0) + VarInt(Protocol version) +
        #   VarInt(len(host)) + host (UTF-8) + Unsigned Short (port) +
        #   VarInt(next state = 1)]
        host_encoded = self.host.encode("utf-8")
        packet_data = b""
        packet_data += self._encode_varint(0)  # packet id = 0
        packet_data += self._encode_varint(4)  # protocol version (hard-coded as 4)
        packet_data += self._encode_varint(len(host_encoded)) + host_encoded
        packet_data += struct.pack(">H", self.port)
        packet_data += self._encode_varint(1)  # next state: status

        # Prepend the length of the packet_data as a VarInt.
        packet = self._encode_varint(len(packet_data)) + packet_data

        s.sendall(packet)

        # Now send the status request packet:
        # Packet: VarInt(1) + VarInt(0)
        s.sendall(self._encode_varint(1) + self._encode_varint(0))

        # Read the response: first a VarInt length...
        length = self._read_varint(s)
        if length < 10:
            s.close()
            raise Exception("Invalid packet length (too short).")
        # Then a VarInt packet id (should be 0)
        packet_id = self._read_varint(s)
        # Then a VarInt string length
        string_len = self._read_varint(s)
        data = self._recv_all(s, string_len)
        s.close()
        try:
            info = json.loads(data.decode("utf-8"))
        except Exception as e:
            raise Exception("JSON parsing failed: " + str(e))
        return info


    def ping_tcp_old(self):
        """
        For legacy (pre-1.7) servers. Sends b'\xFE\x01' and decodes a UTF-16BE response.
        Returns a dictionary with keys: HostName, Players, MaxPlayers, Protocol, Version.
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect((self.host, self.port))
        s.sendall(b"\xFE\x01")
        data = s.recv(512)
        s.close()
        if len(data) < 4 or data[0] != 0xFF:
            raise Exception("Invalid legacy ping response.")
        # Strip the first 3 bytes (packet header) and decode as UTF-16BE.
        data = data[3:]
        try:
            decoded = data.decode("utf-16be")
        except Exception as e:
            raise Exception("UTF-16BE decoding failed: " + str(e))
        if len(decoded) >= 3 and decoded[1:3] == "\xa7" + "1":
            parts = decoded.split("\x00")
            return {
                "HostName": parts[3],
                "Players": int(parts[4]),
                "MaxPlayers": int(parts[5]),
                "Protocol": int(parts[1]),
                "Version": parts[2],
            }
        else:
            parts = decoded.split("\xa7")
            return {
                "HostName": parts[0][:-1],
                "Players": int(parts[1]) if len(parts) > 1 else 0,
                "MaxPlayers": int(parts[2]) if len(parts) > 2 else 0,
                "Protocol": 0,
                "Version": "1.3",
            }
            

    # ────────────────────────────── UDP (Query) Methods ──────────────────────────────

    def query_udp(self):
        """
        Implements the UDP query protocol.
        Returns a dictionary of server info (if successful) and fills self.query_players.
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(self.timeout)
        # A fixed session id.
        session_id = b"\x01\x02\x03\x04"

        # Send handshake request (command 0x09).
        handshake_packet = b"\xFE\xFD" + bytes([0x09]) + session_id
        s.sendto(handshake_packet, (self.host, self.port))
        try:
            data, _ = s.recvfrom(4096)
        except Exception as e:
            s.close()
            raise Exception("UDP handshake failed: " + str(e))
        if len(data) < 5 or data[0] != 0x09:
            s.close()
            raise Exception("Invalid UDP handshake response.")
        # The challenge token is sent as an ASCII string terminated by \0.
        try:
            challenge_token_str = data[5:].split(b"\x00")[0].decode("utf-8")
            challenge_token = int(challenge_token_str)
        except Exception as e:
            s.close()
            raise Exception("Invalid challenge token: " + str(e))

        # Now send the full stat request (command 0x00), appending the challenge token (as a 32-bit signed int)
        # and four null bytes.
        stat_packet = (
            b"\xFE\xFD"
            + bytes([0x00])
            + session_id
            + struct.pack(">l", challenge_token)
            + b"\x00\x00\x00\x00"
        )
        s.sendto(stat_packet, (self.host, self.port))
        try:
            data, _ = s.recvfrom(4096)
        except Exception as e:
            s.close()
            raise Exception("UDP status request failed: " + str(e))
        s.close()
        if len(data) < 5 or data[0] != 0x00:
            raise Exception("Invalid UDP status response.")
        # Remove the header (first 5 bytes).
        payload = data[5:]
        try:
            # The payload is split into two parts:
            # info and player list, separated by b'\x00\x00\x01player_\x00\x00'
            split_data = payload.split(b"\x00\x00\x01player_\x00\x00")
            if len(split_data) != 2:
                raise Exception("Failed to parse status response.")
            info_part = split_data[0]
            players_part = split_data[1][:-2]  # remove trailing two null bytes
            # Parse key-value pairs.
            info_data = info_part.split(b"\x00")
            keys_mapping = {
                b"hostname": "HostName",
                b"gametype": "GameType",
                b"version": "Version",
                b"plugins": "Plugins",
                b"map": "Map",
                b"numplayers": "Players",
                b"maxplayers": "MaxPlayers",
                b"hostport": "HostPort",
                b"hostip": "HostIp",
                b"game_id": "GameName",
            }
            info = {}
            last_key = None
            for i, item in enumerate(info_data):
                if i % 2 == 0:
                    if item in keys_mapping:
                        last_key = keys_mapping[item]
                        info[last_key] = ""
                    else:
                        last_key = None
                else:
                    if last_key is not None:
                        # Decode the value (assume UTF-8).
                        info[last_key] = item.decode("utf-8", errors="replace")
            # Convert numeric values.
            for key in ("Players", "MaxPlayers", "HostPort"):
                try:
                    info[key] = int(info.get(key, 0))
                except Exception:
                    info[key] = 0
            # Process plugins if present.
            if info.get("Plugins"):
                parts = info["Plugins"].split(": ", 1)
                raw_plugins = info["Plugins"]
                info["Software"] = parts[0]
                if len(parts) == 2:
                    info["Plugins"] = parts[1].split("; ")
                else:
                    info["Plugins"] = []
            else:
                info["Software"] = "Vanilla"
            # Process player list.
            players = []
            if players_part:
                players = [p.decode("utf-8", errors="replace") for p in players_part.split(b"\x00") if p]
            self.query_players = players
            return info
        except Exception as e:
            raise Exception("Failed to parse UDP response: " + str(e))


    # ────────────────────────────── Unified Status Method ──────────────────────────────

    def get_status(self):
        """
        Attempts to get the server status using UDP Query first; if that fails,
        falls back to TCP Ping.
        Returns a dictionary that can be converted to JSON.
        """
        start = time.time()
        info = None
        method = None

        # Try UDP query.
        try:
            info = self.query_udp()
            method = "Query"
        except Exception as udp_err:
            udp_error = udp_err  # (could log this)

        if info is not None:
            processed = round(time.time() - start, 4)
            # Determine the platform.
            game_name = info.get("GameName", "")
            if game_name == "MINECRAFT":
                platform = "Minecraft: Java Edition"
            elif game_name == "MINECRAFTPE":
                platform = "Minecraft: Bedrock Edition"
            else:
                platform = game_name
            motd_ingame = info.get("HostName", "")
            clean_motd, html_motd = self.format_motd(motd_ingame)
            result = {
                "status": "Online",
                "platform": platform,
                "gametype": info.get("GameType", ""),
                "motd": {"ingame": motd_ingame, "clean": clean_motd, "html": html_motd},
                "host": {
                    "host": self.host,
                    "hostip": info.get("HostIp", ""),
                    "port": info.get("HostPort", self.port),
                },
                "players": {
                    "max": info.get("MaxPlayers", 0),
                    "online": info.get("Players", 0),
                    "list": self.query_players,
                },
                "version": {"version": info.get("Version", ""), "software": info.get("Software", "")},
                "Plugins": {"list": info.get("Plugins", []), "count": len(info.get("Plugins", []))},
                "queryinfo": {"agreement": "Query", "processed": processed},
            }
            return result
        # If UDP query did not work, try TCP ping.
        try:
            info = self.ping_tcp()
            method = "Ping"
        except Exception as ping_err:
            ping_error = ping_err  # (could log this)

        if info is not None:
            processed = round(time.time() - start, 4)
            # The ping reply (modern JSON) typically contains a "description" field.
            desc = info.get("description", "")
            if isinstance(desc, dict):
                motd_ingame = desc.get("text", "")
            elif isinstance(desc, str):
                motd_ingame = desc
            else:
                motd_ingame = ""
            clean_motd, html_motd = self.format_motd(motd_ingame)
            version_name = info.get("version", {}).get("name", "")
            # Assume version name is like "1.7.10 SomeVersion" and split.
            parts = version_name.split(" ", 1)
            version_clean = parts[1] if len(parts) == 2 else version_name
            result = {
                "status": "Online",

                # "motd": {"ingame": motd_ingame, "clean": clean_motd, "html": html_motd},
                "motd": {"ingame": motd_ingame, "clean": clean_motd, "html": html_motd},
                "host": {"host": self.host, "port": self.port},
                "players": {
                    "max": info.get("players", {}).get("max", 0),
                    "online": info.get("players", {}).get("online", 0),
                },
                "version": {
                    "version": version_clean,
                    "protocol": info.get("version", {}).get("protocol", 0),
                },
                "queryinfo": {"agreement": "Ping", "processed": processed},
            }
            return result

        # If neither method worked, return an offline response.
        processed = round(time.time() - start, 4)
        return {"status": "Offline", "host": self.host, "port": self.port, "queryinfo": {"processed": processed}}


    # ────────────────────────────── Helper Methods ──────────────────────────────

    def _encode_varint(self, value):
        """
        Encodes an integer as a Minecraft VarInt.
        """
        out = b""
        while True:
            temp = value & 0x7F
            value >>= 7
            if value != 0:
                temp |= 0x80
            out += struct.pack("B", temp)
            if value == 0:
                break
        return out


    def _read_varint(self, sock):
        """
        Reads a Minecraft VarInt from a socket.
        """
        num_read = 0
        result = 0
        while True:
            byte = sock.recv(1)
            if len(byte) == 0:
                break
            val = byte[0]
            result |= (val & 0x7F) << (7 * num_read)
            num_read += 1
            if num_read > 5:
                raise Exception("VarInt is too big")
            if (val & 0x80) != 0x80:
                break
        return result


    def _recv_all(self, sock, length):
        """
        Receives exactly 'length' bytes from the socket.
        """
        data = b""
        while len(data) < length:
            chunk = sock.recv(length - len(data))
            if not chunk:
                raise Exception("Connection closed prematurely")
            data += chunk
        return data


    def format_motd(self, motd):
        replacements = {
            "k": "",                        # Obfuscated
            "l": "<b>",                     # Bold
            "m": "<del>",                   # Strikethrough
            "n": "<ins>",                   # Underline
            "o": "<i>",                     # Italic
            "r": '<font color="unset">',    # Reset
            "0": '<font color="#000000">',  # Black
            "1": '<font color="#0000AA">',  # Dark Blue
            "2": '<font color="#00AA00">',  # Dark Green
            "3": '<font color="#00AAAA">',  # Dark Aqua
            "4": '<font color="#AA0000">',  # Dark Red
            "5": '<font color="#AA00AA">',  # Dark Purple
            "6": '<font color="#FFAA00">',  # Gold
            "7": '<font color="#AAAAAA">',  # Gray
            "8": '<font color="#555555">',  # Dark Gray
            "9": '<font color="#5555FF">',  # Blue
            "a": '<font color="#55FF55">',  # Green
            "b": '<font color="#55FFFF">',  # Aqua
            "c": '<font color="#FF5555">',  # Red
            "d": '<font color="#FF55FF">',  # Light Purple
            "e": '<font color="#FFFF55">',  # Yellow
            "f": '<font color="#FFFFFF">',  # White
            "g": '<font color="#dddd00">',  # Minecoin Gold
            "h": '<font color="#e2d3d1">',  # Material Quartz
            "i": '<font color="#cec9c9">',  # Material Iron
            "j": '<font color="#44393a">',  # Material Netherite
            "m": '<font color="#961506">',  # Material Redstone
            "n": '<font color="#b4684d">',  # Material Copper
            "p": '<font color="#deb02c">',  # Material Gold
            "q": '<font color="#119f36">',  # Material Emerald
            "s": '<font color="#2cb9a8">',  # Material Diamond
            "t": '<font color="#20487a">',  # Material Lapis
            "u": '<font color="#9a5cc5">',  # Material Amethyst
        }
        clean_motd = re.sub(r'\\u00a7([0-9a-fr])', '', motd, flags=re.IGNORECASE)
        html_motd = re.sub(
            r'\\u00a7([0-9a-frgkolmn])',
            lambda m: replacements.get(m.group(1).lower(), ""),
            motd,
            flags=re.IGNORECASE
        )
        # Append missing closing tags.
        html_motd = self.close_tags(html_motd)
        return clean_motd, html_motd


    def close_tags(self, html: str) -> str:
        """
        Finds all opened HTML tags in the string and appends missing closing tags.
        Mimics the PHP closeTags() behavior.
        """
        # Match opening tags (e.g. <font>, <b>, <i>, etc.)
        opened_tags = re.findall(r'<([a-z]+)(?:\s[^>]+)?>', html, flags=re.IGNORECASE)
        # Match closing tags (e.g. </font>, </b>, </i>, etc.)
        closed_tags = re.findall(r'</([a-z]+)>', html, flags=re.IGNORECASE)

        # If counts match, assume all tags are properly closed.
        if len(closed_tags) == len(opened_tags):
            return html

        # Reverse the list of opened tags so we close the innermost tags first.
        for tag in reversed(opened_tags):
            if tag not in closed_tags:
                html += f'</{tag}>'
            else:
                # Remove one occurrence of the tag from closed_tags
                closed_tags.remove(tag)
        return html

    
    def _remove_color_codes(self, text):
        """Remove Minecraft color codes from text"""
        return re.sub(r"§[0-9a-frgkolmn]", "", text)
        



# ────────────────────────────── Example Usage ──────────────────────────────
if __name__ == "__main__":
    host = "play.example.com"
    port = 25565
    server = MinecraftServer(host, port, timeout=2)
    status = server.get_status()
    
    print(json.dumps(status, indent=4, ensure_ascii=False))
