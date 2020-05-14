from binascii import hexlify

KEY_LEN = 8


def key_to_id(key):
    return hexlify(key)[-KEY_LEN:].decode()


def id_to_int(id):
    return int(id, 16)


def int_to_id(int_val):
    val = hex(int_val)[2:]
    while len(val) < KEY_LEN:
        val = "0" + val
    return val


def decode_links(complex_type):
    if type(complex_type) == set:
        # set of tuples: seq_num, hash
        res = list()
        for s, h in complex_type:
            res.append((int(s), h.decode('utf-8')))
        return res


def encode_links(complex_type):
    res = set()
    for s, h in complex_type:
        res.add((s, bytes(h, 'utf-8')))
    return res
