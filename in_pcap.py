import os, struct, math
from packet import *
from dsdp import *

class PCAP2DSDP:
	BINARIES = {}
	DSDP_FILES = []
	DSDP_FILES_COMPLETE = []

	def __init__(self, file, raw=False):
		self.DSDP_FILES = []
		if file is None: return
		pcap_linktypes = { 0xA3:"AVS", 0x7F:"RADIOTAP", 0x69:"RAW" }
		pcaprec_hdr_keys = [
			"<IIII",
			[ "ts_sec", "ts_usec", "incl_len", "orig_len" ]
		]
		sender = {}

		length = os.path.getsize(file) - 0x18
		with open(file, "rb") as f:
			pcap_hdr = f.read(0x18)
			if len(pcap_hdr) == 0: return
			try:
				pcap_type = pcap_linktypes[pcap_hdr[0x14]]
			except:
				print("ERROR: Unsupported link type 0x{:X}".format(pcap_hdr[0x14]))
				return
			ex_hdr_len = 0
			c = 0
			pos = 0
			while True:
				c += 1
				pos = f.tell()
				temp = bytearray(f.read(0x10))
				if len(temp) == 0: break
				try:
					temp = struct.unpack(pcaprec_hdr_keys[0], temp)
				except:
					continue
				
				pcaprec_hdr = dict(zip(pcaprec_hdr_keys[1], temp))
				if pcap_type == "AVS":
					temp2 = f.read(8)
					if len(temp2) == 0: break
					ex_hdr_len = struct.unpack(">I", temp2[4:8])[0]
					f.seek(ex_hdr_len - 8, 1)
				elif pcap_type == "RADIOTAP":
					temp2 = f.read(4)
					if len(temp2) == 0: break
					ex_hdr_len = struct.unpack("<H", temp2[2:4])[0]
					if ex_hdr_len == 0xFFFF:
						f.seek(pcaprec_hdr["incl_len"] - 4, 1)
						continue
					else:
						f.seek(ex_hdr_len - 4, 1)
				try:
					buffer = f.read(pcaprec_hdr["incl_len"] - ex_hdr_len)
					if len(buffer) == 0: break
				except:
					break
				
				packet = Packet(buffer)
				source_address = packet.GetSourceAddress()
				if source_address is None: continue
				if source_address not in sender:
					sender[source_address] = {
						"smallest_content_id":0xFF,
						"data":{},
						"rsa":{},
						"beacons":{},
						"valid":False,
					}

				if packet.DATA_TYPE == "BEACON":
					if packet.DATA is None: continue
					(content_id, this_packet, total_packets, data_beacon) = packet.DATA
					if this_packet > 8:
						print("-----", c)
						continue
					sender[source_address]["smallest_content_id"] = min(sender[source_address]["smallest_content_id"], content_id)
					if content_id not in sender[source_address]["beacons"]: sender[source_address]["beacons"][content_id] = {}
					sender[source_address]["beacons"][content_id][this_packet] = packet
					sender[source_address]["valid"] = True
				elif packet.DATA_TYPE == "RSA":
					header_size = struct.unpack("<I", packet.DATA[1][0x33:0x37])[0]
					arm9_size = struct.unpack("<I", packet.DATA[1][0x43:0x47])[0]
					arm7_size = struct.unpack("<I", packet.DATA[1][0x53:0x57])[0]
					rsa_key = (arm9_size, arm7_size)
					sender[source_address]["rsa"][rsa_key] = (packet.DATA[2], header_size, arm9_size, arm7_size)
					sender[source_address]["valid"] = True
				elif packet.DATA_TYPE == "ROM":
					if packet.DATA[0] not in sender[source_address]["data"]: sender[source_address]["data"][packet.DATA[0]] = {}
					if "rom" not in sender[source_address]["data"][packet.DATA[0]]: sender[source_address]["data"][packet.DATA[0]]["rom"] = {}
					if packet.DATA[1] not in sender[source_address]["data"][packet.DATA[0]]["rom"]:
						if "packet_length" not in sender[source_address]["data"][packet.DATA[0]]: sender[source_address]["data"][packet.DATA[0]]["packet_length"] = 0
						sender[source_address]["data"][packet.DATA[0]]["packet_length"] = max(sender[source_address]["data"][packet.DATA[0]]["packet_length"], len(packet.DATA[2]))
						sender[source_address]["data"][packet.DATA[0]]["rom"][packet.DATA[1]] = packet
						sender[source_address]["valid"] = True
		
		for (source_address, s) in sender.items():
			if not s["valid"]: continue
			data_missing = {"header":[], "arm9":[], "arm7":[], "rsa":False}
			raw_packets = {"header":[], "arm9":[], "arm7":[], "rsa":False}
			source_address_str = ''.join(format(x, '02x') for x in source_address[-3:])
			
			# Copy beacons
			for (content_id, item) in s["data"].items():
				if not "beacon" in item:
					if (content_id + s["smallest_content_id"]) in s["beacons"]:
						item["beacon"] = s["beacons"][content_id + s["smallest_content_id"]]

			for (content_id, content) in s["data"].items():
				if "rom" not in content: continue
				pos = 0
				bin = {}
				bin["beacon"] = bytearray()
				bin["rsa"] = bytearray()
				bin["header"] = bytearray()
				bin["arm9"] = bytearray()
				bin["arm7"] = bytearray()

				if 0 not in content["rom"]: continue
				temp = content["rom"][0].DATA[2]
				romtitle = temp[0x00:0x10].decode("ASCII", "ignore")
				arm9_size = struct.unpack("<I", temp[0x2C:0x30])[0]
				arm7_size = struct.unpack("<I", temp[0x3C:0x40])[0]
				rsa_key = (arm9_size, arm7_size)
				if rsa_key not in s["rsa"]:
					print("[{:s}/#{:X}/{:s}] Missing RSA packet".format(str(source_address_str), content_id, romtitle))
					num_packets_header = math.ceil(0x160 / content["packet_length"])
					num_packets_arm9 = math.ceil(arm9_size / content["packet_length"])
					num_packets_arm7 = math.ceil(arm7_size / content["packet_length"])
					data_missing["rsa"] = True
				else:
					bin["rsa"] = s["rsa"][rsa_key][0]
					num_packets_header = math.ceil(s["rsa"][rsa_key][1] / content["packet_length"])
					num_packets_arm9 = math.ceil(s["rsa"][rsa_key][2] / content["packet_length"])
					num_packets_arm7 = math.ceil(s["rsa"][rsa_key][3] / content["packet_length"])
				num_packets_total = num_packets_header + num_packets_arm9 + num_packets_arm7 + 1

				for i in range(0, num_packets_header):
					if pos not in content["rom"]:
						data_missing["header"].append(pos)
					else:
						bin["header"] += content["rom"][pos].DATA[2]
					pos += 1
				if len(data_missing["header"]) > 0:
					print("[{:s}/#{:X}/{:s}] {:d} missing header packet(s)".format(str(source_address_str), content_id, romtitle, len(data_missing["header"])))
					temp = ""
					for i in data_missing["header"]:
						temp += "{:d}, ".format(i)

				for i in range(0, num_packets_arm9):
					if pos not in content["rom"]:
						data_missing["arm9"].append(pos)
					else:
						bin["arm9"] += content["rom"][pos].DATA[2]
					pos += 1
				if len(data_missing["arm9"]) > 0:
					print("[{:s}/#{:X}/{:s}] {:d} missing ARM9 packet(s)".format(str(source_address_str), content_id, romtitle, len(data_missing["arm9"])))
					temp = ""
					for i in data_missing["arm9"]:
						temp += "{:d}, ".format(i)
				
				for i in range(0, num_packets_arm7):
					if pos not in content["rom"]:
						data_missing["arm7"].append(pos)
					else:
						bin["arm7"] += content["rom"][pos].DATA[2]
					pos += 1
				if len(data_missing["arm7"]) > 0:
					print("[{:s}/#{:X}/{:s}] {:d} missing ARM7 packet(s)".format(str(source_address_str), content_id, romtitle, len(data_missing["arm7"])))
					temp = ""
					for i in data_missing["arm7"]:
						temp += "{:d}, ".format(i)
				
				if "beacon" in content and len(content["beacon"]) == 9:
					for i in range(0, len(content["beacon"])):
						bin["beacon"] += content["beacon"][i].DATA[3]
					bin["beacon"] = bin["beacon"][:0x358]
				else:
					print("Banner skipped")

				####################################
				
				arm9_offset = struct.unpack("<I", bin["header"][0x20:0x24])[0]
				arm7_offset = struct.unpack("<I", bin["header"][0x30:0x34])[0]
				banner_offset = struct.unpack("<I", bin["header"][0x68:0x6C])[0]
				if banner_offset == 0:
					banner_offset = arm7_offset + arm7_size
				rsa_offset = banner_offset + 0x840
				bin["rom"] = bytearray(rsa_offset + len(bin["rsa"]))

				bin["rom"][0:len(bin["header"])] = bin["header"]
				bin["rom"][arm9_offset:arm9_offset+len(bin["arm9"])] = bin["arm9"]
				bin["rom"][arm7_offset:arm7_offset+len(bin["arm7"])] = bin["arm7"]
				bin["rom"][banner_offset:banner_offset+len(bin["beacon"])] = bin["beacon"]
				bin["rom"][rsa_offset:rsa_offset+len(bin["rsa"])] = bin["rsa"]
				
				dsdp = DSDP(type=1, banner_template=bin["beacon"], rsa=bin["rsa"], header=bin["header"], arm9=bin["arm9"], arm7=bin["arm7"], raw=raw)
				output = {
					"content_id":content_id,
					"name":dsdp.GetName(),
					"title":dsdp.GetTitle(),
					"title_long":dsdp.GetTitleLong(),
					"server_name":dsdp.GetServerName(),
					"data":dsdp.GetData(),
					"num_packets_header":num_packets_header,
					"num_packets_arm9":num_packets_arm9,
					"num_packets_arm7":num_packets_arm7,
					"num_packets_rsa":1,
					"num_packets_total":num_packets_total,
					"packet_length":content["packet_length"],
				}

				complete = True
				for (i, v) in data_missing.items():
					if isinstance(v, list) and len(v) > 0:
						complete = False
						break
					elif isinstance(v, bool) and i is False:
						complete = False
						break
				self.DSDP_FILES.append((output, complete, bin))
	
	def GetDSDP(self):
		return self.DSDP_FILES
