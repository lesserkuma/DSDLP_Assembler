import struct, hashlib, os
from dsdp import *

class MLN2DSDP:
	BINARIES = {}
	RAW_TITLE = ""

	def __init__(self, file=None, raw=False):
		mlnstate = bytearray()
		self.BINARIES = {}
		if file is None: return
		if isinstance(file, str):
			with open(file, "rb") as f: mlnstate = bytearray(f.read())
		elif isinstance(file, bytearray):
			mlnstate = bytearray(file)
		else:
			return

		if mlnstate[0:4] != b'MELN':
			raise Exception("Error: Invalid melonDS save state file.")
			return
		
		if mlnstate[4] != 0x0A:
			print(f"┗!! Warning: melonDS save state version 0x{mlnstate[4]:02X} is different than this tool was developed for (0x0A).")
		
		try:
			import rsa
		except ImportError:
			raise Exception("Error: Can’t verify RSA signature as the \"rsa\" package is not installed.")
			return
		
		dsi_mode = mlnstate[0x3FFE30:0x3FFE34] == b'HNDA'
		if dsi_mode:
			beacon_offset_mln = 0x393BF4
			rsa_offset_mln = 0x384F80
			header_offset_mln = 0x7FFE24
			arm9_offset_mln = 0x24 + 0x4000
			arm7_offset_mln = 0x2C0024
			pubkey_offset_mln = 0x35EBFC
		else:
			beacon_offset_mln = 0x399634
			rsa_offset_mln = 0x38A6D4
			header_offset_mln = 0x3FFE24
			arm9_offset_mln = 0x24 + 0x4000
			arm7_offset_mln = 0x2C0024
			pubkey_offset_mln = 0x373A28
		
		if hashlib.sha1(mlnstate[header_offset_mln+0xC0:header_offset_mln+0xC0+0x9C]).hexdigest() != "17daa0fec02fc33c0f6abb549a8b80b6613b48ee":
			raise Exception("Invalid header!")
		else:
			arm9_offset = struct.unpack("<I", mlnstate[header_offset_mln+0x20:header_offset_mln+0x24])[0]
			arm7_offset = struct.unpack("<I", mlnstate[header_offset_mln+0x30:header_offset_mln+0x34])[0]
			rsa_offset = struct.unpack("<I", mlnstate[header_offset_mln+0x80:header_offset_mln+0x84])[0]
			arm9_size = struct.unpack("<I", mlnstate[header_offset_mln+0x2C:header_offset_mln+0x30])[0]
			arm7_size = struct.unpack("<I", mlnstate[header_offset_mln+0x3C:header_offset_mln+0x40])[0]
			nds_size = rsa_offset + 0x88
			
			beacon_binary = mlnstate[beacon_offset_mln:beacon_offset_mln+0x358]

			for i in range(0, 2):
				rsa_binary = mlnstate[rsa_offset_mln:rsa_offset_mln+0x88]
				header_binary = mlnstate[header_offset_mln:header_offset_mln+0x160]
				arm9_binary = mlnstate[arm9_offset_mln:arm9_offset_mln+arm9_size]
				arm7_binary = mlnstate[arm7_offset_mln:arm7_offset_mln+arm7_size]
				pubkey = rsa.PublicKey(int.from_bytes(mlnstate[pubkey_offset_mln:pubkey_offset_mln+0x80], byteorder='big'), 65537)
				nds_buffer = bytearray(nds_size)
				nds_buffer[0:len(header_binary)] = header_binary
				nds_buffer[arm9_offset:arm9_offset+len(arm9_binary)] = arm9_binary
				nds_buffer[arm7_offset:arm7_offset+len(arm7_binary)] = arm7_binary
				nds_buffer[rsa_offset:rsa_offset+len(rsa_binary)] = rsa_binary
				
				# RSA check
				rsa_ok = False
				signature = rsa_binary[0x04:0x84]
				hash_calc = \
					hashlib.sha1(header_binary).digest() + \
					hashlib.sha1(arm9_binary).digest() + \
					hashlib.sha1(arm7_binary).digest() + \
					rsa_binary[0x84:0x88]
				try:
					rsa.verify(hash_calc, signature, pubkey)
					rsa_ok = True
				except rsa.pkcs1.VerificationError:
					rsa_ok = False
				
				if rsa_ok:
					break
				else:
					arm9_offset_mln -= 0x4000
					continue
		
		bin = {}
		bin["beacon"] = beacon_binary
		bin["rsa"] = rsa_binary
		bin["header"] = header_binary
		bin["arm9"] = arm9_binary
		bin["arm7"] = arm7_binary
		bin["rom"] = nds_buffer
		bin["banner"] = bytearray()
		
		if arm9_size > 0x300000:
			raise Exception("ARM9 section is too large")
		if arm7_size > 0x40000:
			raise Exception("ARM7 section is too large")
		
		if not os.path.exists("pubkey.bin"):
			with open("pubkey.bin", "wb") as f:
				f.write(mlnstate[pubkey_offset_mln:pubkey_offset_mln+0x80])

		self.BINARIES = bin
		self.DSDP = DSDP(type=1, rsa=bin["rsa"], header=bin["header"], arm9=bin["arm9"], arm7=bin["arm7"], rom=bin["rom"], banner_template=bin["beacon"], raw=raw)
	
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
