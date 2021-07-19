from Crypto.Cipher import AES


blob = "CJDSCPCJHMSTC636ARCAYOCIFQ5GUGIFOQ3XKBCHHYEXY63EPBVQ===="
blob2 = "B1CT0RHAMF0rd"


def slippy(msg: str, key: str) -> str:
    out = ""
    for c in msg:
        if 'a' <= c <= 'z':
        c = chr(((ord(c) - ord('a')) + 26) % 26)
        elif 'A' <= c <= 'Z':
        c = chr(((ord(c) - ord('A')) + 26) % 26)
        out += c
    
    return out


def flipper(msg: bytes, key: bytes) -> bytes:
    return bytes([msg[i] ^ key[i % len(key)] for i in range(len(msg))])


def slibber_slam(msg: str, r: int, f: int) -> str:
    pass


def flubber(msg: str) -> str:
    pass


def flingus(msg: str) -> bytes:
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    n = 0
    i = 0

    for c in msg:
        p = (len(msg) - (i + 1))
        num += ord(c) * (62 ** p)
        i += 1
    
    


def flash(blob: str) -> str:
    blob = "".join([chr(int(i, 22)) for i in blob.split(":")])
    blob = flingus(blob)

    
    cipher = AES.new(key, AES.MODE_CBC, iv=b)
    blob = cipher.decrypt(blob)

    return blob