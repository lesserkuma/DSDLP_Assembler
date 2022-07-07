from http import server
import struct
from dsdp import *
from in_srl import SRL2DSDP

class NCH2DSDP:
    BINARIES = {}
    LANGUAGE = 0
    TITLE = ""
    TITLE_LONG = ""

    def __init__(self, file=None, raw=False):
        self.BINARIES = {}
        if file is None: return
        with open(file, "rb") as f: buffer = bytearray(f.read())
        language = struct.unpack(">I", buffer[0x10:0x14])[0]
        offset_rom = struct.unpack(">I", buffer[0x14:0x18])[0]
        self.LANGUAGE = language
        
        rom = buffer[offset_rom:]
        nch_names = {
            0:"ニンテンドーCh", # JA
            1:"NintendoCh", # EN
            2:"Nintendo-K", # DE
            3:"C.Nintendo", # FR
            4:"C.Nintendo", # ES
            5:"C.Nintendo", # IT
            6:"Nintendo-k", # NL
        }
        if language in nch_names:
            server_name = nch_names[language]
        else:
            server_name = "NintendoCh"

        nds2dsdp = SRL2DSDP(rom)
        bin = nds2dsdp.GetBinaries()
        
        if "banner" not in bin:
            bin["banner"] = bytearray([0x00] * 0x840)
            bin["banner"][0:2] = struct.pack("<H", 0x0001) # Banner Version
            bin["banner_unused"] = bytearray()
        else:
            bin["banner_unused"] = bytearray(bin["banner"])
        
        title = buffer[0x1C:0x7C].decode("UTF-16BE").split("\x00")[0].strip()
        description = buffer[0x7E:0x7E+0xC0].decode("UTF-16BE").split("\x00")[0].strip()

        text = title.encode("UTF-16LE")
        text = text + bytearray([0x00] * (0x100 - len(text)))
        bin["banner"][0x240:0x340] = text # Title JA
        bin["banner"][0x340:0x440] = text # Title EN
        bin["banner"][0x440:0x540] = text # Title FR
        bin["banner"][0x540:0x640] = text # Title DE
        bin["banner"][0x640:0x740] = text # Title IT
        bin["banner"][0x740:0x840] = text # Title ES
        bin["banner"][2:4] = struct.pack("<H", crc16(bin["banner"][0x20:0x840]))
        
        bin["banner_template"] = buffer[:offset_rom]
        
        bin["beacon"] = bytearray(0x358)
        bin["beacon"][0:0x20] = bin["banner"][0x220:0x240]
        bin["beacon"][0x20:0x220] = bin["banner"][0x20:0x220]
        bin["beacon"][0x220] = 0x0A # Color
        bin["beacon"][0x221] = len(server_name)
        temp = server_name.encode("UTF-16LE")
        bin["beacon"][0x222:0x222+len(temp)] = temp
        bin["beacon"][0x236] = 0x02
        title_raw = title.encode("UTF-16LE")[:0x60]
        description_raw = description.encode("UTF-16LE")[:0xC0]
        bin["beacon"][0x238:0x238+len(title_raw)] = title_raw
        bin["beacon"][0x298:0x298+len(description_raw)] = description_raw

        bin["rom"] = rom
        self.DSDP = DSDP(type=3, rsa=bin["rsa"], header=bin["header"], arm9=bin["arm9"], arm7=bin["arm7"], banner=bin["banner"], banner_unused=bin["banner_unused"], banner_template=bin["banner_template"], rom=bin["rom"], raw=raw)
        if raw:
            self.DSDP = DSDP(type=3, rsa=bin["rsa"], header=bin["header"], arm9=bin["arm9"], arm7=bin["arm7"], raw=raw)
        self.BINARIES = bin

        s = ""
        for char in title.replace("\n", " ").replace("\r", " "):
            if char.isprintable() or char == "　":
                s += char
        self.TITLE = re.sub(r"[<>:\"/\\|\?\*]", " ", s).replace("  ", " ")
        self.TITLE_LONG = title + "\n" + description
    
    def GetLanguage(self):
        return self.LANGUAGE
    
    def GetDSDP(self):
        bin = self.BINARIES
        dsdp = self.DSDP
        output = {
            "name":dsdp.GetName(),
            "title":self.TITLE,
            "title_long":self.TITLE_LONG,
            "server_name":dsdp.GetServerName(),
            "data":dsdp.GetData()
        }
        return [ (output, bin) ]
