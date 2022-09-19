from http import server
import struct
from dsdp import *

class SRL2DSDP:
    BINARIES = {}
    RAW_TITLE = ""

    def __init__(self, file=None, raw=False):
        buffer = bytearray()
        self.BINARIES = {}
        if file is None: return
        if isinstance(file, str):
            with open(file, "rb") as f: buffer = bytearray(f.read())
        elif isinstance(file, bytearray):
            buffer = bytearray(file)
        else:
            return
        
        bin = {}
        bin["banner_template"] = bytearray()
        bin["banner_unused"] = bytearray()
        size_rom = struct.unpack("<I", buffer[0x80:0x84])[0]

        bin["rom"] = buffer[:size_rom + 0x88]
        server_name = bytearray()

        if buffer[-4:] == b'DSDP':
            rom_size = struct.unpack("<I", buffer[-0x80:-0x80+4])[0]
            offset_banner_template = struct.unpack("<I", buffer[-0x78:-0x78+4])[0]
            if offset_banner_template != 0:
                size_banner_template = struct.unpack("<I", buffer[-0x74:-0x74+4])[0]
                bin["banner_template"] = buffer[offset_banner_template:offset_banner_template+size_banner_template]
            offset_banner_unused = struct.unpack("<I", buffer[-0x68:-0x68+4])[0]
            if offset_banner_unused != 0:
                size_banner_unused = struct.unpack("<I", buffer[-0x64:-0x64+4])[0]
                bin["banner_unused"] = buffer[offset_banner_unused:offset_banner_unused+size_banner_unused]
            buffer = buffer[:rom_size]
        
        rsa_pos = buffer.rfind(b'\x61\x63\x01\x00')
        if rsa_pos == -1: raise Exception("RSA missing")
        bin["rsa"] = buffer[rsa_pos:rsa_pos+0x88]
        bin["header"] = buffer[0:0x160]
        offset_arm9 = struct.unpack("<I", bin["header"][0x20:0x24])[0]
        size_arm9 = struct.unpack("<I", bin["header"][0x2C:0x30])[0]
        offset_arm7 = struct.unpack("<I", bin["header"][0x30:0x34])[0]
        size_arm7 = struct.unpack("<I", bin["header"][0x3C:0x40])[0]
        offset_banner = struct.unpack("<I", bin["header"][0x68:0x6C])[0]
        bin["arm9"] = buffer[offset_arm9:offset_arm9+size_arm9]
        bin["arm7"] = buffer[offset_arm7:offset_arm7+size_arm7]

        server_name_len = 0
        if buffer[0x200:0x210] == b'DS DOWNLOAD PLAY':
            rsa_pos = buffer.rfind(b'\x61\x63\x01\x00')
            if rsa_pos == -1: raise Exception("RSA missing")
            bin["rsa"] = buffer[rsa_pos:rsa_pos+0x88]
            bin["header"] = buffer[0x220:0x220+0x160]
            offset_banner = struct.unpack("<I", buffer[0x68:0x6C])[0]
            if offset_banner != 0:
                server_name = buffer[0x390:0x3A6]
                server_name_len = len(server_name.decode("UTF-16LE").strip("\x00"))
                bin["banner_template"] = bytearray(0x358)
                bin["banner_template"][0x000:0x020] = buffer[offset_banner+0x220:offset_banner+0x240]
                bin["banner_template"][0x020:0x220] = buffer[offset_banner+0x020:offset_banner+0x220]
                bin["banner_template"][0x220] = 0x0A
                bin["banner_template"][0x221] = server_name_len
                bin["banner_template"][0x222:0x238] = buffer[0x390:0x3A6]
                title = buffer[offset_banner+0x240:offset_banner+0x340].split(b"\x0A\x00")
                bin["banner_template"][0x238:len(title[0])] = title[0]
                desc = bytearray()
                for i in range(0, len(title)):
                    if i == 0: continue
                    desc += title[i]
                bin["banner_template"][0x298:len(desc)] = desc
                bin["banner_template"] = bin["banner_template"][:0x358]
                bin["rom"] = None

            offset_arm9 = struct.unpack("<I", buffer[0x20:0x24])[0]
            size_arm9 = struct.unpack("<I", buffer[0x2C:0x30])[0]
            offset_arm7 = struct.unpack("<I", buffer[0x30:0x34])[0]
            size_arm7 = struct.unpack("<I", buffer[0x3C:0x40])[0]
            offset_banner = struct.unpack("<I", buffer[0x68:0x6C])[0]
            bin["arm9"] = buffer[offset_arm9:offset_arm9+size_arm9]
            bin["arm7"] = buffer[offset_arm7:offset_arm7+size_arm7]
            buffer[0:0x160] = buffer[0x220:0x380]
            buffer[0x160:0x3C0] = bytearray(0x260)
        
        if offset_banner == 0:
            bin["banner"] = bytearray(0x840)
        else:
            bin["banner"] = buffer[offset_banner:offset_banner+0x840]
        
        if raw:
            bin["rom"] = None

            if len(bin["banner"]) > 0:
                bin["fake_beacon"] = bytearray(0x358)
                bin["fake_beacon"][0:0x20] = bin["banner"][0x220:0x240]
                bin["fake_beacon"][0x20:0x220] = bin["banner"][0x20:0x220]
                bin["fake_beacon"][0x220] = 0x0A
                bin["fake_beacon"][0x221] = server_name_len
                bin["fake_beacon"][0x222:0x222+len(server_name)] = server_name
                bin["fake_beacon"][0x236] = 0x02
                title = bin["banner"][0x240:0x340].split(b"\n\x00")
                desc = bytearray(b"\n\x00".join(title[1:]))[:0xC0]
                bin["fake_beacon"][0x238:0x238+len(title[0])] = title[0]
                bin["fake_beacon"][0x298:0x298+len(desc)] = desc
                bin["fake_beacon"] = bin["fake_beacon"][:0x358]
                self.RAW_TITLE = title[0]
            bin["banner"] = bytearray()
        
        if size_arm9 > 0x300000:
            raise Exception("ARM9 section is too large")
        if size_arm7 > 0x40000:
            raise Exception("ARM7 section is too large")

        self.BINARIES = bin
        self.DSDP = DSDP(type=2, rsa=bin["rsa"], header=bin["header"], arm9=bin["arm9"], arm7=bin["arm7"], banner=bin["banner"], rom=bin["rom"], banner_template=bin["banner_template"], banner_unused=bin["banner_unused"], raw=raw)
    
    def GetBinaries(self):
        return self.BINARIES
    
    def GetDSDP(self):
        bin = self.BINARIES
        dsdp = self.DSDP
        if len(self.RAW_TITLE) > 0:
            s = ""
            for char in self.RAW_TITLE.decode("UTF-16LE", "ignore").split("\x00")[0].strip().replace("\n", " ").replace("\r", " "):
                if char.isprintable() or char == "　":
                    s += char
            title = re.sub(r"[<>:\"/\\|\?\*]", " ", s).replace("  ", " ")
        else:
            title = dsdp.GetTitle()

        output = {
            "name":dsdp.GetName(),
            "title":title,
            "server_name":dsdp.GetServerName(),
            "data":dsdp.GetData()
        }
        return [ (output, bin) ]
