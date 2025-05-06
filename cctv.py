import argparse


class Cctv:
    def __init__(self, data):
        self.data = bytearray(data)

        self.index_array = []
        self.offset_array = []
        self.pes = bytearray()
        self.ts_count = 0


    @staticmethod
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


    @staticmethod
    def read_signed(data, offset=0):
        return int.from_bytes(data[offset:], byteorder='little', signed=True)


    @staticmethod
    def write_signed(value: int) -> bytes:
        return value.to_bytes(4, byteorder='little', signed=False)


    @staticmethod
    def decrypt_64bit_block(block, key):
        block = [
            Cctv.read_signed(block),
            Cctv.read_signed(block, 4)
        ]
        key = [
            Cctv.read_signed(key),
            Cctv.read_signed(key, 4),
            Cctv.read_signed(key, 8),
            Cctv.read_signed(key, 12)
        ]

        Cctv.tea_decrypt(block, key)

        return Cctv.write_signed(block[0]) + Cctv.write_signed(block[1])


    @staticmethod
    def remove_scep_3_bytes(data):
        output = bytearray()
        i = 0
        while i < len(data):
            if i + 2 < len(data) and data[i] == 0 and data[i + 1] == 0 and data[i + 2] == 3:
                output.extend([0, 0])
                i += 3
            else:
                output.append(data[i])
                i += 1
        return output


    @staticmethod
    def decrypt_nal_unit(unit):
        unit = Cctv.remove_scep_3_bytes(unit)

        key = unit[16:32]
        iterations = (len(unit) - 32) // 80
        i = 0

        while i < iterations:
            offset = 32 + i * 80
            unit[offset:offset + 8] = Cctv.decrypt_64bit_block(unit[offset:offset + 8], key)
            i += 1

        return unit


    @staticmethod
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


    @staticmethod
    def parse_nal_array(data):
        begin = 0
        total = len(data)
        while begin < total:
            begin += 3
            end = Cctv.find_nal_unit_start(data, begin + 1, total)
            nal_unit_type = data[begin] & 0x1f
            if nal_unit_type == 1 or nal_unit_type == 5 or nal_unit_type == 25:
                input_data = data[begin:end]
                output_data = Cctv.decrypt_nal_unit(input_data)
                data[begin:begin + len(output_data)] = output_data
            begin = end


    def scatter_pes(self, data):
        k = 0
        for i in range(len(self.offset_array)):
            start = self.offset_array[i]
            end = self.index_array[i] + 188
            for j in range(start, end):
                data[j] = self.pes[k]
                k += 1


    def parse_ts_packets(self, data, index):
        pid = ((data[index + 1] & 0x1f) << 8) + data[index + 2]
        pusi = (data[index + 1] & 0x40) >> 6

        if pid != 0x100:
            return

        afc = (data[index + 3] & 0x30) >> 4

        if pusi == 1:
            if self.ts_count > 0:
                self.parse_nal_array(self.pes)
                self.scatter_pes(data)
                self.ts_count = 0

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
            self.index_array = [index]
            self.pes = payload
            self.offset_array = [payload_index]
        else:
            self.index_array.append(index)
            self.pes.extend(payload)
            self.offset_array.append(payload_index)

        self.ts_count += 1


    def decrypt_segment(self):
        for i in range(0, len(self.data), 188):
            if self.data[i] != 0x47:
                exit("invalid ts packet")
            self.parse_ts_packets(self.data, i)

        if self.ts_count > 0:
            self.parse_nal_array(self.pes)
            self.scatter_pes(self.data)

        return self.data


if __name__ == '__main__':
    parser = argparse.ArgumentParser("CCTV.com TEA Fragment decrypter (github.com/DevLARLEY)")
    parser.add_argument("infile", type=argparse.FileType("rb"), help="Input file")
    parser.add_argument("outfile", type=argparse.FileType("wb"), help="Output file")

    args = parser.parse_args()

    in_data = args.infile.read()

    cctv = Cctv(in_data)
    new_data = cctv.decrypt_segment()

    args.outfile.write(new_data)

    args.infile.close()
    args.outfile.close()
