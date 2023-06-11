import binascii, struct

packet_types = { 0x8000:"BEACON", 0x2802:"DATA" }
data_types = { 0x1103:"RSA", 0x1104:"ROM" }

class Packet:
	VALID = False
	SOURCE_ADDR = None
	TARGET_ADDR = None
	PACKET_TYPE = None
	PACKET_DATA = None
	DATA_TYPE = None
	DATA = None

	def __init__(self, buffer):
		crc32_calc = binascii.crc32(buffer[0:-4])
		crc32_data = struct.unpack(">I", buffer[-4:])[0]
		self.VALID = crc32_calc == crc32_data
		self.PACKET_DATA = buffer
		temp = struct.unpack(">H", buffer[0:2])[0]
		if temp not in packet_types: return
		self.SOURCE_ADDR = buffer[0x0A:0x10]
		self.TARGET_ADDR = buffer[0x04:0x0A]
		self.PACKET_TYPE = packet_types[temp]

		if self.PACKET_TYPE == "BEACON" and self.TARGET_ADDR == bytearray([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]):
			temp = buffer.find(bytearray([ 0xDD, 0x88, 0x00, 0x09, 0xBF ]))
			if temp < 0: return
			try:
				content_id = buffer[temp + 0x1F]
			except:
				return
			if content_id > 20: return
			if buffer[0x50] & 2 == 2: return # user data
			beacon_type = struct.unpack(">H", buffer[temp+0x14:temp+0x16])[0]
			if beacon_type not in (0x7003, 0x700B): return
			this_packet = buffer[temp + 0x21]
			total_packets = buffer[temp + 0x25]
			if this_packet > total_packets: return
			self.DATA_TYPE = "BEACON"
			self.DATA = (content_id, this_packet, total_packets, buffer[temp+0x28:temp+0x8A])

		elif self.PACKET_TYPE == "DATA" and self.TARGET_ADDR == bytearray([0x03, 0x09, 0xBF, 0x00, 0x00, 0x00]):
			if len(buffer) < 0x1F: return
			temp = struct.unpack(">H", buffer[0x1D:0x1F])[0]
			if temp not in data_types:
				return
			self.DATA_TYPE = data_types[temp]
			if self.DATA_TYPE == "RSA":
				rsa_key = struct.unpack(">I", buffer[0x42:0x42+4])[0]
				self.DATA = (rsa_key, buffer[0:0x5B], buffer[0x5B:0x5B+0x88])
			elif self.DATA_TYPE == "ROM":
				content_id = buffer[0x1F]
				this_packet = struct.unpack("<H", buffer[0x21:0x23])[0]
				self.DATA = (content_id, this_packet, buffer[0x23:-7])
	
	def GetSourceAddress(self):
		return self.SOURCE_ADDR
