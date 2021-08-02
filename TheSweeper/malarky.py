from Cryptodome.Cipher import AES
from base64 import b32decode, b64decode
from math import log2


def slippy(msg: str, key: int) -> str:
    out = ""
    for c in msg:
        if 'a' <= c <= 'z':
            c = chr((((ord(c) - ord('a')) + key) % 26) + 0x61)
        elif 'A' <= c <= 'Z':
            c = chr((((ord(c) - ord('A')) + key) % 26) + 0x41)
        out += c
    
    return out


def flipper(msg: bytes, key: bytes) -> bytes:
    return bytes([msg[i] ^ key[i % len(key)] for i in range(len(msg))])


def slibber_slam(msg: str, r: int, o: int) -> str:
    o = o % (r + r - 2)
    l = len(msg) // 2 + ((o > 1) + (o > r))
    matrix = [['\0'] * l for _ in range(r)]
    row = 0
    col = 2 * (o > 0)
    i = o - 1
    j = o - r
    for c in msg:
        matrix[row][col] = c
        col += 1 + (row == 0 or row == r - 1)
        if col >= l:
            col = 0
            row += 1
        if col < 2:
            col += (i > 0)
            col += (j < 0)
            i -= 1
            j -= 1
    
    out = ""

    if o < r:
        row = o
    else:
        row = (r - 1) - (o - (r - 1))
    col = int(o >= r)
    for _ in range(len(msg)):
        out += matrix[row][col]
        if (col & 1) == 0:
            if row < r - 1:
                row += 1
            else:
                row -= 1
                col += 1
        else:
            if row > 1:
                row -= 1
            else:
                row -= 1
                col += 1
    
    return out


def flingus(msg: str) -> bytes:
    m = { c: i for i, c in enumerate("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz") }
    n = 0
    i = 1
    
    for c in msg:
        if c not in m: continue
        p  = (len(msg) - (i))
        n += m[c] * (62 ** p)
        i += 1

    bits = int(log2(n))
    
    bits >>= 3
    out = [0] * (bits + 1)
    j = 0
    
    for i in range(bits, -1, -1):
        out[j] = (n >> (i << 3)) & 0xff
        j += 1
    
    return bytes(out)


def flash(blob: str) -> str:
    blob1 = "CJDSCPCJHMSTC636ARCAYOCIFQ5GUGIFOQ3XKBCHHYEXY63EPBVQ===="
    blob2 = "B1CT0RHAMF0rd"
    blob3 = "c14df11a343d454744464536574755346733818338aa167d"
    blob = "".join([chr(int(i, 22)) for i in blob.split(":")])
    blob = flingus(blob)

    blob1 = b32decode(blob1)
    blob1 = flipper(blob1, blob2.encode("utf-8"))
    blob1 = slippy(blob1.decode("utf-8"), 19).encode("utf-8")

    blob3 = slibber_slam(blob3, 3, 7)
    blob3 = "".join([chr(int(blob3[i:i + 2], 16)) for i in range(0, len(blob3), 2)])
    blob3 = b64decode(blob3)
    blob3 = flipper(blob3, b"F0xX3J@m3s")
    
    cipher = AES.new(blob1, AES.MODE_CBC, iv=blob3)
    blob = cipher.decrypt(blob)

    return blob[:len(blob) - blob[-1]].decode("utf-8")