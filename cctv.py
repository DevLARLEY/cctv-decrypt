import argparse


def tea_decrypt(v, k):
    delta = 0x9E3779B9
    sum_ = (delta << 4) & 0xFFFFFFFF

    v0 = v[0] & 0xFFFFFFFF
    v1 = v[1] & 0xFFFFFFFF

    k0 = k[0] & 0xFFFFFFFF
    k1 = k[1] & 0xFFFFFFFF
    k2 = k[2] & 0xFFFFFFFF
    k3 = k[3] & 0xFFFFFFFF

    for _ in range(16):
        v1 = (v1 - (((v0 << 4) + k2) ^ (v0 + sum_) ^ ((v0 >> 5) + k3))) & 0xFFFFFFFF
        v0 = (v0 - (((v1 << 4) + k0) ^ (v1 + sum_) ^ ((v1 >> 5) + k1))) & 0xFFFFFFFF
        sum_ = (sum_ - delta) & 0xFFFFFFFF

    v[0] = v0
    v[1] = v1


def read_signed(data, offset=0):
    return int.from_bytes(data[offset:], byteorder='little', signed=True)

def write_signed(value: int) -> bytes:
    return value.to_bytes(4, byteorder='little', signed=False)


def decrypt_64bit_block(data, key):
    data = [read_signed(data), read_signed(data, 4)]
    key = [read_signed(key),read_signed(key, 4),read_signed(key, 8),read_signed(key, 12)]

    tea_decrypt(data, key)

    return write_signed(data[0]) + write_signed(data[1])


def remove_scep_3_bytes(data):
    output = bytearray()
    i = 0
    while i < len(data):
        if i + 3 < len(data) and data[i] == 0 and data[i+1] == 0 and data[i+2] == 3 and data[i+3] == 3:
            output.extend([0, 0, 3])
            i += 4
        else:
            output.append(data[i])
            i += 1
    return bytearray(output)


def decrypt_nal_unit(unit):
    unit = remove_scep_3_bytes(unit)

    key = unit[16:32]
    iterations = (len(unit) - 32) // 80
    i = 0

    while i < iterations:
        offset = 32 + i * 80
        unit[offset:offset + 8] = decrypt_64bit_block(unit[offset:offset + 8], key)
        i += 1

    return unit


def find_nal_unit_start(data, pos, total):
    while pos + 2 < total:
        if data[pos + 2] == 0:
            if pos + 3 < total and data[pos + 1] == 0 and data[pos + 3] == 1:
                return pos + 1
            pos += 2
        elif data[pos + 2] == 1:
            if data[pos] == 0 and data[pos + 1] == 0:
                return pos
            pos += 3
        else:
            pos += 3
    return total



def parse_nal_array(data):
    begin = 0
    total = len(data)
    while begin < total:
        begin += 3
        end = find_nal_unit_start(data, begin + 1, total)
        nal_unit_type = data[begin] & 0x1f
        if nal_unit_type == 1 or nal_unit_type == 5 or nal_unit_type == 25:
            input_data = data[begin:end]
            output_data = decrypt_nal_unit(input_data)
            data[begin:begin + len(output_data)] = output_data
        begin = end


def scatter_pes(data, ctx):
    k = 0
    for i in range(len(ctx["offset_array"])):
        start = ctx["offset_array"][i]
        end = ctx["index_array"][i] + 188
        for j in range(start, end):
            data[j] = ctx["pes"][k]
            k += 1


def parse_ts_packet(data, index, ctx):
    pid = ((data[index + 1] & 0x1f) << 8) + data[index + 2]
    pusi = (data[index + 1] & 0x40) >> 6

    if pid != 0x100:
        return

    afc = (data[index + 3] & 0x30) >> 4

    if pusi == 1:
        if ctx["ts_count"] > 0:
            parse_nal_array(ctx["pes"])
            scatter_pes(data, ctx)
            ctx["ts_count"] = 0

    match afc:
        case 1:
            payload_index = index + 4
            payload = data[payload_index:index+188]
        case 2:
            exit("afc 2 = no payload")
            pass
        case 3:
            afl = data[index+4]
            payload_index = index + 4 + 1 + afl
            payload = data[payload_index:index+188]
        case _:
            exit("invalid afc")

    if pusi == 1:
        ctx["index_array"] = [index]
        ctx["pes"] = payload
        ctx["offset_array"] = [payload_index]
    else:
        ctx["index_array"].append(index)
        ctx["pes"].extend(payload)
        ctx["offset_array"].append(payload_index)

    ctx["ts_count"] += 1


def parse_ts(data):
    data = bytearray(data)

    ctx = {
        "index_array": [],
        "pes": [],
        "offset_array": [],
        "ts_count": 0
    }

    for i in range(0, len(data), 188):
        if data[i] != 0x47:
            exit("invalid ts packet")
        parse_ts_packet(data, i, ctx)

    if ctx["ts_count"] > 0:
        parse_nal_array(ctx["pes"])
        scatter_pes(data, ctx)

    return data


if __name__ == '__main__':
    parser = argparse.ArgumentParser("CCTV.com TEA Fragment decrypter (github.com/DevLARLEY)")
    parser.add_argument("infile", type=argparse.FileType("rb"), help="Input file")
    parser.add_argument("outfile", type=argparse.FileType("wb"), help="Output file")

    args = parser.parse_args()

    data = args.infile.read()
    new_data = parse_ts(data)
    args.outfile.write(new_data)

    args.infile.close()
    args.outfile.close()
