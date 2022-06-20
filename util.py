import array

def crc16(buffer):
    poly = 0xA001
    table = array.array('H')
    for byte in range(256):
        crc = 0
        for bit in range(8):
            if (byte ^ crc) & 1:
                crc = (crc >> 1) ^ poly
            else:
                crc >>= 1
            byte >>= 1
        table.append(crc)
    
    value = 0xFFFF
    for ch in buffer:
        value = table[ch ^ (value & 0xFF)] ^ (value >> 8)
    return value
