import struct, re
from util import crc16

class DSDP:
	DATA = None
	BINARIES = {}
	TITLE = ""
	SERVER_NAME = ""
	FONT_WIDTHS = { " ":2,"!":3,"\"":3,"#":7,"$":5,"%":7,"&":6,"'":1,"(":4,")":4,"*":7,"+":5,",":3,"-":5,".":3,"/":5,"0":5,"1":3,"2":5,"3":5,"4":6,"5":5,"6":5,"7":5,"8":5,"9":5,":":3,";":3,"<":5,"=":5,">":5,"?":4,"@":7,"A":5,"B":5,"C":5,"D":5,"E":4,"F":4,"G":5,"H":5,"I":1,"J":4,"K":5,"L":4,"M":5,"N":5,"O":5,"P":5,"Q":5,"R":5,"S":4,"T":5,"U":5,"V":5,"W":5,"X":5,"Y":5,"Z":4,"[":4,"\\":5,"]":4,"^":3,"_":5,"`":2,"a":5,"b":5,"c":5,"d":5,"e":5,"f":4,"g":5,"h":5,"i":1,"j":3,"k":4,"l":2,"m":7,"n":5,"o":5,"p":5,"q":5,"r":4,"s":4,"t":4,"u":5,"v":5,"w":5,"x":5,"y":5,"z":5,"{":5,"|":3,"}":5,"~":7,"\x00":3,"\x00":9,"\x00":9,"\x00":9,"©":9,"®":9,"°":3,"±":5,"´":3,"·":3,"¿":5,"À":5,"Á":5,"Â":5,"Ã":5,"Ä":5,"Å":5,"Æ":7,"Ç":5,"È":4,"É":4,"Ê":4,"Ë":4,"Ì":5,"Í":5,"Î":5,"Ï":5,"Ð":6,"Ñ":5,"Ò":5,"Ó":5,"Ô":5,"Õ":5,"Ö":5,"×":5,"Ø":7,"Ù":5,"Ú":5,"Û":5,"Ü":5,"Ý":5,"ß":5,"à":5,"á":5,"â":5,"ã":5,"ä":5,"å":5,"æ":7,"ç":5,"è":5,"é":5,"ê":5,"ë":5,"ì":3,"í":3,"î":3,"ï":3,"ð":5,"ñ":5,"ò":5,"ó":5,"ô":5,"õ":5,"ö":5,"÷":5,"ø":7,"ù":5,"ú":5,"û":5,"ü":5,"ý":5,"Œ":7,"œ":7,"\x00":1,"\x00":5,"\x00":3,"\x00":3,"\x00":3,"":9,"\x00":9,"※":9,"€":6,"™":9,"←":9,"↑":9,"→":9,"↓":9,"∞":9,"⸫":9,"■":9,"□":9,"▲":9,"△":9,"▼":9,"▽":9,"◆":9,"◇":9,"○":9,"◎":9,"●":9,"★":9,"☆":9,"♪":9,"♭":9,"　":9,"、":9,"。":9,"「":9,"」":9,"〒":9,"ぁ":9,"あ":9,"ぃ":9,"い":9,"ぅ":9,"う":9,"ぇ":9,"え":9,"ぉ":9,"お":9,"か":9,"が":9,"き":9,"ぎ":9,"く":9,"ぐ":9,"け":9,"げ":9,"こ":9,"ご":9,"さ":9,"ざ":9,"し":9,"じ":9,"す":9,"ず":9,"せ":9,"ぜ":9,"そ":9,"ぞ":9,"た":9,"だ":9,"ち":9,"ぢ":9,"っ":9,"つ":9,"づ":9,"て":9,"で":9,"と":9,"ど":9,"な":9,"に":9,"ぬ":9,"ね":9,"の":9,"は":9,"ば":9,"ぱ":9,"ひ":9,"び":9,"ぴ":9,"ふ":9,"ぶ":9,"ぷ":9,"へ":9,"べ":9,"ぺ":9,"ほ":9,"ぼ":9,"ぽ":9,"ま":9,"み":9,"む":9,"め":9,"も":9,"ゃ":9,"や":9,"ゅ":9,"ゆ":9,"ょ":9,"よ":9,"ら":9,"り":9,"る":9,"れ":9,"ろ":9,"ゎ":9,"わ":9,"を":9,"ん":9,"ァ":9,"ア":9,"ィ":9,"イ":9,"ゥ":9,"ウ":9,"ェ":9,"エ":9,"ォ":9,"オ":9,"カ":9,"ガ":9,"キ":9,"ギ":9,"ク":9,"グ":9,"ケ":9,"ゲ":9,"コ":9,"ゴ":9,"サ":9,"ザ":9,"シ":9,"ジ":9,"ス":9,"ズ":9,"セ":9,"ゼ":9,"ソ":9,"ゾ":9,"タ":9,"ダ":9,"チ":9,"ヂ":9,"ッ":9,"ツ":9,"ヅ":9,"テ":9,"デ":9,"ト":9,"ド":9,"ナ":9,"ニ":9,"ヌ":9,"ネ":9,"ノ":9,"ハ":9,"バ":9,"パ":9,"ヒ":9,"ビ":9,"ピ":9,"フ":9,"ブ":9,"プ":9,"ヘ":9,"ベ":9,"ペ":9,"ホ":9,"ボ":9,"ポ":9,"マ":9,"ミ":9,"ム":9,"メ":9,"モ":9,"ャ":9,"ヤ":9,"ュ":9,"ユ":9,"ョ":9,"ヨ":9,"ラ":9,"リ":9,"ル":9,"レ":9,"ロ":9,"ヮ":9,"ワ":9,"ヲ":9,"ン":9,"ヴ":9,"ヵ":9,"ヶ":9,"・":9,"ー":9,"Ⓐ":9,"Ⓑ":9,"Ⓧ":9,"Ⓨ":9,"Ⓛ":9,"Ⓡ":9,"⊕":9,"\x00":9,"\x00":9,"\x00":9,"\x00":9,"\x00":9,"\x00":9,"\x00":9,"\x00":9,"\x00":9,"\x00":9,"\x00":9,"\x00":9,"\x00":9,"♠":9,"♦":9,"♥":9,"♣":9,"\x00":9,"\x00":9,"\x00":9,"\x00":9,"\x00":9,"š":3,"¢":6,"£":5,"！":9,"？":9,"／":9,"＼":9 }

	def __init__(self, type, banner_template=bytearray(), rsa=bytearray(), header=bytearray(), arm9=bytearray(), arm7=bytearray(), banner=bytearray(), banner_unused=bytearray(), rom=None, raw=False):
		if rsa is None or header is None or arm9 is None or arm7 is None:
			raise Exception("More data required")
		
		bin = {
			"banner_template":banner_template,
			"rsa":rsa,
			"header":header,
			"arm9":arm9,
			"arm7":arm7,
			"banner":banner,
			"banner_unused":banner_unused,
			"imported_rom":rom,
		}
		
		dsdp_offset_arm9 = struct.unpack("<I", bin["header"][0x20:0x24])[0]
		dsdp_offset_arm7 = struct.unpack("<I", bin["header"][0x30:0x34])[0]
		dsdp_offset_fnt = struct.unpack("<I", bin["header"][0x40:0x44])[0]
		dsdp_size_fnt = struct.unpack("<I", bin["header"][0x44:0x48])[0]
		dsdp_offset_fat = struct.unpack("<I", bin["header"][0x48:0x4C])[0]
		dsdp_size_fat = struct.unpack("<I", bin["header"][0x4C:0x50])[0]
		dsdp_offset_banner = struct.unpack("<I", bin["header"][0x68:0x6C])[0]
		dsdp_size_rom = struct.unpack("<I", bin["header"][0x80:0x84])[0]
		dsdp_offset_rsa = dsdp_size_rom
		
		raw_title = bytearray()
		title_long = ""
		banner_too_long = False
		if type == 2:
			temp_title = bin["banner"][0x340:0x440].split(b"\n\x00")
			if len(temp_title) > 3:
				banner_too_long = True
			else:
				for temp in temp_title:
					i = temp.decode("UTF-16LE").split("\x00")[0].strip()
					if self._GetTextWidth(i) > 140:
						banner_too_long = True
			if len(temp_title) == 1:
				raw_title = temp_title[0]
			else:
				for i in range(0, len(temp_title) - 1):
					raw_title += temp_title[i] + b"\x20\x00"
				raw_title = raw_title[:-2]
			romfile = rom
		elif type == 3:
			romfile = rom
		
		if type != 2 or banner_too_long or romfile is None:
			if len(banner) > 0:
				if len(bin["banner_unused"]) == 0:
					bin["banner_unused"] = bytearray(bin["banner"])
				temp_title = bin["banner"][0x340:0x440].split(b"\n\x00")
				raw_title = temp_title[0]
				server_name = temp_title[-1].decode("UTF-16LE").split("\x00")[0].strip()
				title = raw_title.decode("UTF-16LE").split("\x00")[0].strip()
				text = self._FormatTitle(title)
				text = text.encode("UTF-16LE") 
				text = text + bytearray([0x00] * (0x100 - len(text)))
				bin["banner"][0x240:0x340] = text # Title JA
				bin["banner"][0x340:0x440] = text # Title EN
				bin["banner"][0x440:0x540] = text # Title FR
				bin["banner"][0x540:0x640] = text # Title DE
				bin["banner"][0x640:0x740] = text # Title IT
				bin["banner"][0x740:0x840] = text # Title ES
				bin["banner"][2:4] = struct.pack("<H", crc16(bin["banner"][0x20:0x840]))
			
			elif len(banner) == 0 and len(banner_template) != 0:
				bin["banner"] = bytearray([0x00] * 0x840)
				bin["banner"][0:2] = struct.pack("<H", 0x0001) # Banner Version
				bin["banner"][0x20:0x220] = bin["banner_template"][0x20:0x220] # Icon
				bin["banner"][0x220:0x240] = bin["banner_template"][0:0x20] # Palette
				server_name = bin["banner_template"][0x222:0x222+0x14].decode("UTF-16LE", "ignore").split("\x00")[0].strip()
				self.SERVER_NAME = server_name
				raw_title = bin["banner_template"][0x238:0x298]
				title = raw_title.decode("UTF-16LE", "ignore").split("\x00")[0].strip()
				text = self._FormatTitle(title)
				text = text.encode("UTF-16LE") 
				text = text + bytearray([0x00] * (0x100 - len(text)))
				bin["banner"][0x240:0x340] = text # Title JA
				bin["banner"][0x340:0x440] = text # Title EN
				bin["banner"][0x440:0x540] = text # Title FR
				bin["banner"][0x540:0x640] = text # Title DE
				bin["banner"][0x640:0x740] = text # Title IT
				bin["banner"][0x740:0x840] = text # Title ES
				bin["banner"][2:4] = struct.pack("<H", crc16(bin["banner"][0x20:0x840]))

				description = bin["banner_template"][0x298:0x358].decode("UTF-16LE", "ignore").split("\x00")[0].strip()
				title_long = title + "\n" + description

			if type in (1, 4) or romfile is None:
				bin["banner_template"] += bytearray([0x00] * (0x358 - len(bin["banner_template"])))
				bin["banner_template"] = bin["banner_template"][:0x358]

				if dsdp_offset_banner != 0 and len(bin["banner"]) == 0:
					bin["banner"] = bytearray(0x840)
				
				romfile = bytearray(dsdp_size_rom + len(bin["rsa"]))
				romfile[0:len(bin["header"])] = bin["header"]
				romfile[dsdp_offset_arm9:dsdp_offset_arm9+len(bin["arm9"])] = bin["arm9"]
				romfile[dsdp_offset_arm7:dsdp_offset_arm7+len(bin["arm7"])] = bin["arm7"]
				romfile[dsdp_offset_rsa:dsdp_offset_rsa+len(bin["rsa"])] = bin["rsa"]
			
			if not raw and dsdp_offset_banner != 0:
				romfile[dsdp_offset_banner:dsdp_offset_banner+len(bin["banner"])] = bin["banner"]
		
		####
		if not raw:
			size_orig_rom = len(romfile)
			romfile += bytearray(((len(romfile) + 0x10) & 0xFFFFFFF0) - len(romfile))
			offset_extra_section = len(romfile)
			romfile += b'----------------'
			romfile += b'DS DOWNLOAD PLAY'
			
			romfile += b'----------------'
			if len(bin["banner_template"]) > 0:
				dsdp_offset_banner_template = len(romfile)
				romfile += bin["banner_template"]
				romfile += bytearray(((len(romfile) + 0x10) & 0xFFFFFFF0) - len(romfile))
			else:
				dsdp_offset_banner_template = 0
			
			dsdp_offset_banner_unused = 0
			if dsdp_offset_banner == 0:
				if len(bin["banner"]) > 0:
					dsdp_offset_banner = len(romfile)
					romfile += bin["banner"]
					romfile += bytearray(((len(romfile) + 0x10) & 0xFFFFFFF0) - len(romfile))
				if len(bin["banner_unused"]) > 0:
					dsdp_offset_banner_unused = len(romfile)
					romfile += bin["banner_unused"]
					romfile += bytearray(((len(romfile) + 0x10) & 0xFFFFFFF0) - len(romfile))
			else:
				if len(bin["banner_unused"]) > 0:
					dsdp_offset_banner_unused = len(romfile)
					romfile += bin["banner_unused"]
					romfile += bytearray(((len(romfile) + 0x10) & 0xFFFFFFF0) - len(romfile))

			# Footer
			pointer_base = len(romfile)
			offset_game_title = pointer_base
			romfile += bytearray(0x100)
			temp = raw_title[:0x70]
			romfile[pointer_base:pointer_base+len(temp)] = temp
			romfile[pointer_base+0x80:pointer_base+0x84] = struct.pack("<I", size_orig_rom)
			romfile[pointer_base+0x84:pointer_base+0x88] = struct.pack("<I", offset_extra_section)
			if dsdp_offset_banner_template > 0:
				romfile[pointer_base+0x88:pointer_base+0x8C] = struct.pack("<I", dsdp_offset_banner_template)
				romfile[pointer_base+0x8C:pointer_base+0x90] = struct.pack("<I", len(bin["banner_template"]))
			if dsdp_offset_banner > 0:
				romfile[pointer_base+0x90:pointer_base+0x94] = struct.pack("<I", dsdp_offset_banner)
				romfile[pointer_base+0x94:pointer_base+0x98] = struct.pack("<I", len(bin["banner"]))
			if dsdp_offset_banner_unused > 0:
				romfile[pointer_base+0x98:pointer_base+0x9C] = struct.pack("<I", dsdp_offset_banner_unused)
				romfile[pointer_base+0x9C:pointer_base+0xA0] = struct.pack("<I", len(bin["banner_unused"]))
			romfile[pointer_base+0xA0:pointer_base+0xA4] = struct.pack("<I", offset_game_title)
			romfile[pointer_base+0xFC:pointer_base+0x100] = b"DSDP" # Magic
			romfile[pointer_base+0xFA] = 0 # Version
			romfile[pointer_base+0xFB] = type # (1=from capture, 2=converted from existing .nds/.srl, 3=from Nintendo Channel)

		self.RAW_TITLE = raw_title
		self.TITLE_LONG = title_long
		self.BINARIES = bin
		self.DATA = romfile
	
	def _FormatTitle(self, title):
		title_width = 0
		title_temp = ""
		title_new = ""
		title_pos = 0
		for i in range(0, len(title)):
			title_temp += title[i]
			title_width = self._GetTextWidth(title_temp)
			if title_width >= 140:
				separated = False
				sep_chars = [ " ", "　", "\n" ]
				for sep_char in sep_chars:
					if sep_char in title_temp:
						title_new += title_temp[title_pos:title_temp.rindex(sep_char)] + "\n"
						title_pos = title_temp.rindex(sep_char)
						separated = True
						break
				if not separated:
					sep_chars = [ "!", "?", "~", "～", "！", "？", "」", "・" ]
					for sep_char in sep_chars:
						if sep_char in title_temp:
							title_new += title_temp[title_pos:title_temp.rindex(sep_char)] + sep_char + "\n"
							title_pos = title_temp.rindex(sep_char)
							separated = True
							break
				if not separated:
					title_new += title_temp[0:len(title_temp)-1] + "\n"
					title_pos = len(title_temp) - 2
					separated = True
				title_temp = title_temp[title_pos+1:]
				title_pos = 0
		title_new += title_temp
		text = title_new.strip()
		return text

	def _GetTextWidth(self, text):
		width = 0
		for char in text:
			if char in self.FONT_WIDTHS:
				width += self.FONT_WIDTHS[char] + 1
			else:
				width += 10
		return width

	def GetData(self):
		return self.DATA

	def GetName(self):
		name = self.BINARIES["header"][0:0xC].decode("ASCII", "ignore").rstrip("\x00").strip()
		code = self.BINARIES["header"][0xC:0x10].decode("ASCII", "ignore").rstrip("\x00").strip()
		rev = "{:d}".format(self.BINARIES["header"][0x1E])
		r = name + "_" + code + "-" + rev
		return re.sub(r"[<>:\"/\\|\?\*]", "", r)
	
	def GetTitle(self):
		str = ""
		for char in self.RAW_TITLE.decode("UTF-16LE", "ignore").split("\x00")[0].strip().replace("\n", " ").replace("\r", " "):
			if char.isprintable() or char == "　":
				str += char
		return re.sub(r"[<>:\"/\\|\?\*]", " ", str).replace("  ", " ")

	def GetTitleLong(self):
		return self.TITLE_LONG

	def GetServerName(self):
		return self.SERVER_NAME
