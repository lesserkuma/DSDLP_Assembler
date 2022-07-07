import binascii, os, subprocess, argparse, struct, hashlib, zlib, datetime, re, shutil, datetime
from in_pcap import PCAP2DSDP
from in_nch import NCH2DSDP
from in_srl import SRL2DSDP
APPNAME = "DSDLP Assembler"
APPNAME_FULL = "{:s} v0.2".format(APPNAME)
DATES = {}

def check_rsa(data):
    if os.path.exists("ndsrsa.exe"):
        with open("temp.bin", "wb") as f: f.write(data)
        p = subprocess.run(["ndsrsa.exe", "verify", "nintendo", "temp.bin"], capture_output=True, text=True)
        return "signature = valid" in p.stdout
    else:
        print("! Couldn’t verify RSA signature as ndsrsa.exe is missing")
        return None

def export(basedir, o, binaries, filedate=None, region="", type=0):
    if filedate is not None:
        dt = datetime.datetime.fromtimestamp(filedate)
    else:
        dt = datetime.datetime.now()

    dir = "{:s}/{:s}".format(basedir, o["server_name"])
    if not os.path.exists(dir): os.makedirs(dir)
    crc32_nds = binascii.crc32(o["data"])
    crc32_bcn = None
    if "beacon" in binaries:
        crc32_global = binascii.crc32(o["data"] + binaries["beacon"])
        crc32_bcn = binascii.crc32(binaries["beacon"])
    else:
        crc32_global = binascii.crc32(o["data"])
    
    if o["title"].strip() == "":
        fn = "{:s}".format(o["name"])
        fn_glob = "{:s} [{:08X}]".format(fn, crc32_global)
    else:
        fn = "{:s} ({:s})".format(o["title"], o["name"])
        fn_glob = "{:s} [{:08X}]".format(fn, crc32_global)
    
    rsa_check = check_rsa(o["data"])
    if rsa_check is not False:
        print("┗━━ {:s}".format(fn_glob))
        if not os.path.exists(dir + "/{:s}".format(fn_glob)): os.makedirs(dir + "/{:s}".format(fn_glob))
        
        csv = {}
        sections = {"{:s} [{:08X}].nds".format(fn, crc32_nds):o["data"]}
        if "beacon" in binaries: sections["{:s} [{:08X}].bcn".format(fn, crc32_bcn)] = binaries["beacon"]
        for (section, data) in sections.items():
            with open(dir + "/{:s}/{:s}".format(fn_glob, section), "wb") as f: f.write(data)
            csv[section] = {}
            csv[section]["forcename"] = ""
            csv[section]["extension"] = section[-3:]
            csv[section]["size"] = len(data)
            csv[section]["crc32"] = "{:08x}".format(zlib.crc32(data) & 0xFFFFFFFF)
            csv[section]["md5"] = hashlib.md5(data).hexdigest()
            csv[section]["sha1"] = hashlib.sha1(data).hexdigest()
            csv[section]["sha256"] = hashlib.sha256(data).hexdigest()
        
        if type == 3:
            fni = os.path.split(o["infile"])[1]
            shutil.copy(o["infile"], dir + "/{:s}/{:s}".format(fn_glob, fni))
            with open(o["infile"], "rb") as fi: data = fi.read()
            csv[fni] = {}
            csv[fni]["forcename"] = fni
            csv[fni]["size"] = len(data)
            csv[fni]["crc32"] = "{:08x}".format(zlib.crc32(data) & 0xFFFFFFFF)
            csv[fni]["md5"] = hashlib.md5(data).hexdigest()
            csv[fni]["sha1"] = hashlib.sha1(data).hexdigest()
            csv[fni]["sha256"] = hashlib.sha256(data).hexdigest()

        with open(dir + "/{:s}/post.txt".format(fn_glob), "wb") as f:
            if dt.strftime("%Y-%m-%d") not in DATES: DATES[dt.strftime("%Y-%m-%d")] = []
            if not "{:s}/{:s}".format(dir, fn_glob) in DATES[dt.strftime("%Y-%m-%d")]:
                DATES[dt.strftime("%Y-%m-%d")].append("{:s}/{:s}".format(dir, fn_glob))

            s = "[DS Download Play] {:s}\n\n".format(fn_glob)
            s += "[b]Game Name:[/b] {:s}\n".format(fn_glob)
            s += "[b]System:[/b] DS Download Play\n"
            s += "[b]Type:[/b] Playable demo version\n"
            s += "[b]Region:[/b] {:s}\n".format(region)
            if region == "Japan":
                s += "[b]Languages:[/b] Japanese\n"
            else:
                s += "[b]Languages:[/b] \n"
            s += "[b]Dumper:[/b] \n"
            s += "[b]Dump Date:[/b] {:s}\n".format(dt.strftime("%Y-%m-%d"))
            s += "[b]Tool:[/b] {:s}\n".format(APPNAME_FULL)
            s += "\n[b]Files:[/b]\n"
            for csv_file in csv:
                s += "[code]\n"
                s += "* File Name:       {:s}\n".format(csv_file)
                if type == 1:
                    if csv_file.endswith("bcn"):
                        s += "* File Size:       {:d} bytes (9 packets captured)\n".format(csv[csv_file]["size"])
                    elif csv_file.endswith("nds"):
                        s += "* File Size:       {:d} bytes ({:d} packets captured)\n".format(csv[csv_file]["size"], o["num_packets_total"])
                else:
                    s += "* File Size:       {:d} bytes\n".format(csv[csv_file]["size"])
                s += "* CRC32:           {:s}\n".format(csv[csv_file]["crc32"])
                s += "* MD5:             {:s}\n".format(csv[csv_file]["md5"])
                s += "* SHA-1:           {:s}\n".format(csv[csv_file]["sha1"])
                s += "* SHA-256:         {:s}\n".format(csv[csv_file]["sha256"])
                if csv_file.endswith("nds"):
                    s += "* Game Title:      {:s}\n".format(binaries["header"][0:0x0C].decode("ASCII", "ignore").strip("\x00"))
                    s += "* Game Code:       {:s}\n".format(binaries["header"][0x0C:0x10].decode("ASCII", "ignore").strip("\x00"))
                    s += "* Revision:        {:d}\n".format(binaries["header"][0x1E])
                    s += "* RSA Validation:  {:s}\n".format("OK" if rsa_check else "Unknown")
                    header_offset = 0
                    header_size = 0x160
                    arm9_offset = struct.unpack("<I", binaries["header"][0x20:0x24])[0]
                    arm9_size = struct.unpack("<I", binaries["header"][0x2C:0x30])[0]
                    arm7_offset = struct.unpack("<I", binaries["header"][0x30:0x34])[0]
                    arm7_size = struct.unpack("<I", binaries["header"][0x3C:0x40])[0]
                    rsa_offset = struct.unpack("<I", binaries["header"][0x80:0x84])[0]
                    s += "* Header Location: 0x{:X}–0x{:X}\n".format(header_offset, header_offset + header_size)
                    s += "* ARM9 Location:   0x{:X}–0x{:X}\n".format(arm9_offset, arm9_offset + arm9_size)
                    s += "* ARM7 Location:   0x{:X}–0x{:X}\n".format(arm7_offset, arm7_offset + arm7_size)
                    s += "* RSA Location:    0x{:X}–0x{:X}\n".format(rsa_offset, rsa_offset + 0x88)
                elif csv_file.endswith("bcn"):
                    s += "* Title:           {:s}\n".format(binaries["beacon"][0x238:0x298].decode("UTF-16LE", "ignore").strip("\x00"))
                    desc = binaries["beacon"][0x298:0x358].decode("UTF-16LE", "ignore").split("\x00")[0].split("\n")
                    s += "* Description:     {:s}\n".format(desc[0])
                    if len(desc) > 1:
                        for i in range(1, len(desc)):
                            s += "                   {:s}\n".format(desc[i])
                    s += "* Server Name:     {:s}\n".format(binaries["beacon"][0x222:0x236].decode("UTF-16LE", "ignore").strip("\x00"))
                s += "[/code]\n"
            f.write(s.encode("UTF-8-SIG"))

    else:
        print("┗XX [RSA Check Failed] {:s}".format(fn_glob))

def do_nch(files, basedir, region=""):
    for file in files:
        print("< {:s}".format(file))
        nch2dsdp = NCH2DSDP(file, raw=True)
        dsdp = nch2dsdp.GetDSDP()
        for (o, binaries) in dsdp:
            dt = os.path.getmtime(file)
            o["infile"] = file
            export(basedir, o, binaries, dt, region, 3)

def do_srl(files, basedir):
    for file in files:
        print("< {:s}".format(file))
        nds2dsdp = SRL2DSDP(file, raw=True)
        dsdp = nds2dsdp.GetDSDP()
        for (o, binaries) in dsdp:
            o["server_name"] = ""
            dt = os.path.getmtime(file)
            binaries["beacon"] = binaries["fake_beacon"]
            export(basedir, o, binaries, dt)

def do_cap(files, basedir, region=""):
    for file in files:
        print("· {:s}".format(file))
        pcap2dsdp = PCAP2DSDP(file, raw=True)
        dsdp = pcap2dsdp.GetDSDP()
        for (o, complete, binaries) in dsdp:
            if not complete:
                try:
                    print("┗?? [Incomplete] {:s}".format(binaries["header"][0:0x10].decode("ASCII", "ignore")))
                except:
                    print("┗?? [Incomplete] {:s}".format(file))
            elif len(o["server_name"].strip()) == 0:
                print("┗?? [Server Name Unknown] {:s}".format(binaries["header"][0:0x10].decode("ASCII", "ignore")))
            else:
                o["infile"] = file
                dt = os.path.getmtime(file)
                m = re.search("capture\-(\d{4})(\d{2})(\d{2})\-\d{6}", file)
                if m is not None and len(m.groups()) >= 3:
                    dt = datetime.datetime(int(m.groups()[0]), int(m.groups()[1]), int(m.groups()[2])).timestamp()
                export(basedir, o, binaries, dt, region, 1)


class ArgParseCustomFormatter(argparse.ArgumentDefaultsHelpFormatter, argparse.RawDescriptionHelpFormatter): pass
def __main__():
    print("\n{:s}\nby Lesserkuma\n".format(APPNAME))
    parser = argparse.ArgumentParser(formatter_class=ArgParseCustomFormatter)
    parser = argparse.ArgumentParser()
    parser.add_argument("infile", help="", type=str)
    parser.add_argument("--outdir", help="", type=str, default="./output")
    args = parser.parse_args()
    ext = os.path.splitext(args.infile)
    if ext[1] in (".cap", ".pcap"):
        print("Mode: PCAP Wi-Fi Capture\n")
        do_cap([args.infile], args.outdir)
    elif ext[1] in (".bin"):
        print("Mode: Nintendo Channel DLC .bin file\n")
        do_nch([args.infile], args.outdir)
    elif ext[1] in (".nds"):
        print("Mode: Existing .nds file (clean-up)\n")
        do_srl([args.infile], args.outdir)
    if os.path.exists("temp.bin"): os.unlink("temp.bin")

__main__()
