import os, io
import streamlit as st
from PIL import Image
import re

# ---- AES-256 ----
SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]
INV_SBOX = [0]*256
for i, v in enumerate(SBOX):
    INV_SBOX[v] = i
RCON = [0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36,0x6C,0xD8,0xAB,0x4D,0x9A]

def gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1: p ^= a
        hi = a & 0x80
        a = ((a << 1) & 0xFF) ^ (0x1B if hi else 0)
        b >>= 1
    return p

def bytes_to_state(block16: bytes):
    s = [[0]*4 for _ in range(4)]
    for c in range(4):
        for r in range(4):
            s[r][c] = block16[c*4 + r]
    return s

def state_to_bytes(state):
    out = bytearray(16)
    for c in range(4):
        for r in range(4):
            out[c*4 + r] = state[r][c]
    return bytes(out)

def sub_bytes(s):
    for r in range(4):
        for c in range(4):
            s[r][c] = SBOX[s[r][c]]

def inv_sub_bytes(s):
    for r in range(4):
        for c in range(4):
            s[r][c] = INV_SBOX[s[r][c]]

def shift_rows(s):
    s[1] = s[1][1:] + s[1][:1]
    s[2] = s[2][2:] + s[2][:2]
    s[3] = s[3][3:] + s[3][:3]

def inv_shift_rows(s):
    s[1] = s[1][-1:] + s[1][:-1]
    s[2] = s[2][-2:] + s[2][:-2]
    s[3] = s[3][-3:] + s[3][:-3]

def mix_columns(s):
    for c in range(4):
        a0,a1,a2,a3 = s[0][c], s[1][c], s[2][c], s[3][c]
        s[0][c] = gmul(a0,2) ^ gmul(a1,3) ^ a2 ^ a3
        s[1][c] = a0 ^ gmul(a1,2) ^ gmul(a2,3) ^ a3
        s[2][c] = a0 ^ a1 ^ gmul(a2,2) ^ gmul(a3,3)
        s[3][c] = gmul(a0,3) ^ a1 ^ a2 ^ gmul(a3,2)

def inv_mix_columns(s):
    for c in range(4):
        a0,a1,a2,a3 = s[0][c], s[1][c], s[2][c], s[3][c]
        s[0][c] = gmul(a0,14) ^ gmul(a1,11) ^ gmul(a2,13) ^ gmul(a3,9)
        s[1][c] = gmul(a0,9)  ^ gmul(a1,14) ^ gmul(a2,11) ^ gmul(a3,13)
        s[2][c] = gmul(a0,13) ^ gmul(a1,9)  ^ gmul(a2,14) ^ gmul(a3,11)
        s[3][c] = gmul(a0,11) ^ gmul(a1,13) ^ gmul(a2,9)  ^ gmul(a3,14)

def add_round_key(s, rk_bytes: bytes):
    k = bytes_to_state(rk_bytes)
    for r in range(4):
        for c in range(4):
            s[r][c] ^= k[r][c]

def rot_word(w): return w[1:] + w[:1]
def sub_word(w): return [SBOX[b] for b in w]

def key_expansion_256(key32: bytes):
    assert len(key32) == 32
    Nk, Nb, Nr = 8, 4, 14
    words = [list(key32[i*4:(i+1)*4]) for i in range(Nk)]
    i = Nk
    while len(words) < Nb*(Nr+1):
        temp = words[-1].copy()
        if i % Nk == 0:
            temp = sub_word(rot_word(temp))
            temp[0] ^= RCON[i // Nk]
        elif i % Nk == 4:
            temp = sub_word(temp)
        neww = [(words[i-Nk][j] ^ temp[j]) & 0xFF for j in range(4)]
        words.append(neww)
        i += 1
    round_keys = []
    for r in range(Nr+1):
        chunk = words[4*r:4*r+4]
        round_keys.append(bytes(sum(chunk, [])))
    return round_keys 

def encrypt_block_256(block16: bytes, rks):
    s = bytes_to_state(block16)
    add_round_key(s, rks[0])
    for rnd in range(1,14):
        sub_bytes(s); shift_rows(s); mix_columns(s); add_round_key(s, rks[rnd])
    sub_bytes(s); shift_rows(s); add_round_key(s, rks[14])
    return state_to_bytes(s)

def decrypt_block_256(block16: bytes, rks):
    s = bytes_to_state(block16)
    add_round_key(s, rks[14])
    for rnd in range(13,0,-1):
        inv_shift_rows(s); inv_sub_bytes(s); add_round_key(s, rks[rnd]); inv_mix_columns(s)
    inv_shift_rows(s); inv_sub_bytes(s); add_round_key(s, rks[0])
    return state_to_bytes(s)

def pkcs7_pad(data: bytes, bs=16):
    padlen = bs - (len(data) % bs)
    return data + bytes([padlen])*padlen

def pkcs7_unpad(data: bytes, bs=16):
    if not data or (len(data) % bs) != 0:
        raise ValueError("PKCS7 length invalid")
    padlen = data[-1]
    if padlen < 1 or padlen > bs: raise ValueError("PKCS7 pad invalid")
    if data[-padlen:] != bytes([padlen])*padlen: raise ValueError("PKCS7 content invalid")
    return data[:-padlen]

def xor_bytes(a: bytes, b: bytes): return bytes(x ^ y for x, y in zip(a,b))

def aes256_cbc_encrypt(plaintext: bytes, key32: bytes, iv16: bytes):
    rks = key_expansion_256(key32)
    pt = pkcs7_pad(plaintext, 16)
    out = bytearray()
    prev = iv16
    for i in range(0, len(pt), 16):
        blk = xor_bytes(pt[i:i+16], prev)
        ct  = encrypt_block_256(blk, rks)
        out += ct
        prev = ct
    return iv16 + bytes(out)

def aes256_cbc_decrypt(iv_ct: bytes, key32: bytes):
    if len(iv_ct) < 16: raise ValueError("Ciphertext terlalu pendek")
    iv, ct = iv_ct[:16], iv_ct[16:]
    if len(ct) % 16 != 0: raise ValueError("Ciphertext tidak kelipatan 16")
    rks = key_expansion_256(key32)
    out = bytearray()
    prev = iv
    for i in range(0, len(ct), 16):
        blk = ct[i:i+16]
        ptb = decrypt_block_256(blk, rks)
        out += xor_bytes(ptb, prev)
        prev = blk
    return pkcs7_unpad(bytes(out), 16)

# ----- Steganografi LSB -----

def bytes_to_bits(data: bytes) -> str:
    return ''.join(f'{b:08b}' for b in data)

def bits_to_bytes(bits: str) -> bytes:
    return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))

def encode_file_to_image(file_bytes: bytes, image_bytes: bytes) -> bytes:
    payload = len(file_bytes).to_bytes(4, 'big') + file_bytes
    bits = bytes_to_bits(payload)

    image = Image.open(io.BytesIO(image_bytes)).convert('RGB')
    w, h = image.size
    total_capacity = w*h*3

    if len(bits) > total_capacity:
        need_px = (len(bits) + 2)//3
        raise ValueError(f"Gambar tidak cukup: perlu ~{need_px} piksel, tersedia {w*h}.")

    px = image.load()
    idx = 0
    for y in range(h):
        for x in range(w):
            if idx >= len(bits): break
            r,g,b = px[x,y]
            if idx < len(bits): r = (r & 0xFE) | int(bits[idx]); idx += 1
            if idx < len(bits): g = (g & 0xFE) | int(bits[idx]); idx += 1
            if idx < len(bits): b = (b & 0xFE) | int(bits[idx]); idx += 1
            px[x,y] = (r,g,b)
        if idx >= len(bits): break

    out = io.BytesIO()
    image.save(out, format='PNG')
    return out.getvalue()

def decode_file_from_image(image_bytes: bytes) -> bytes:
    image = Image.open(io.BytesIO(image_bytes)).convert('RGB')
    w, h = image.size
    px = image.load()

    length_bits = []
    count = 0
    for y in range(h):
        for x in range(w):
            r,g,b = px[x,y]
            for ch in (r,g,b):
                if count < 32:
                    length_bits.append(str(ch & 1))
                    count += 1
                if count >= 32: break
            if count >= 32: break
        if count >= 32: break
    if len(length_bits) < 32:
        raise ValueError("Gagal membaca panjang payload.")
    payload_len = int.from_bytes(bits_to_bytes(''.join(length_bits)), 'big')

    need_bits = payload_len * 8
    payload_bits = []
    seen = 0
    consumed = 0
    for y in range(h):
        for x in range(w):
            r,g,b = px[x,y]
            for ch in (r,g,b):
                if consumed < 32:
                    consumed += 1
                    continue
                if seen >= need_bits: break
                payload_bits.append(str(ch & 1))
                seen += 1
            if seen >= need_bits: break
        if seen >= need_bits: break

    if seen < need_bits:
        raise ValueError("Payload di gambar lebih sedikit dari panjang yang dinyatakan.")
    return bits_to_bytes(''.join(payload_bits))

# Streamlit Application 

st.set_page_config(page_title="AES-256 + Stego LSB", page_icon="🔐", layout="centered")
st.title("🔐 Secure File")

st.subheader("Selamat Datang di Aplikasi Secure File")

st.markdown("<p style='text-align:center; font-size:18px;'>Solusi Aman Menyembunyikan & Melindungi Informasi Rahasia Anda</p>", unsafe_allow_html=True)

st.markdown(
    """
    <div style="text-align: justify;">
        Aplikasi ini dirancang sebagai sarana untuk melindungi kerahasiaan dan integritas informasi melalui kombinasi algoritma kriptografi AES-256 dengan teknik steganografi LSB. AES-256 berfungsi mengenkripsi data sehingga isinya tidak dapat dibaca tanpa kunci, sedangkan metode steganografi LSB memungkinkan hasil enkripsi tersebut disisipkan ke dalam citra digital tanpa mengubah kualitas visual gambar. Dengan pendekatan ini, file penting dapat disembunyikan sekaligus diamankan, sehingga tidak hanya menjaga kerahasiaan isi dokumen tetapi juga menyamarkan keberadaannya dari pihak yang tidak berhak. Aplikasi ini diharapkan mampu memberikan solusi sederhana namun efektif dalam penerapan keamanan data di lingkungan akademik maupun kebutuhan umum.
    </div>
    """,
    unsafe_allow_html=True
)

st.markdown("---")

st.title("🔐 Secure File")

mode = st.radio("Pilih Mode:", ["Enkripsi + Sisipkan", "Ekstraksi + Dekripsi"])

key_text = st.text_input("Kunci (min. 8 karakter, maks. 32 karakter, harus mengandung huruf kecil, huruf besar, angka, dan karakter khusus)", type="password", max_chars=32)

# Fungsi untuk validasi kunci
def is_valid_key(key):
    # Cek panjang minimal dan maksimal
    if len(key) < 8 or len(key) > 32:
        return False
    # Cek kombinasi karakter
    if not re.search(r'[a-z]', key): return False
    if not re.search(r'[A-Z]', key): return False
    if not re.search(r'[0-9]', key): return False
    if not re.search(r'[^a-zA-Z0-9\s]', key): return False
    return True

key_bytes = None
if key_text:
    if is_valid_key(key_text):
        # Padding kunci dengan '0' jika kurang dari 32 karakter
        padded_key = key_text.ljust(32, '0')
        key_bytes = padded_key.encode()
    else:
        # Menampilkan peringatan berdasarkan jenis kesalahan
        if len(key_text) < 8:
            st.warning("Kunci tidak valid: kurang dari 8 karakter.")
        elif len(key_text) > 32:
            st.warning("Kunci tidak valid: melebihi 32 karakter.")
        else:
            st.warning("Kunci tidak valid. Pastikan: mengandung huruf kecil, huruf besar, angka, dan karakter khusus.")

if mode == "Enkripsi + Sisipkan":
    up_file = st.file_uploader("📄 Upload file yang akan dienkripsi & disisipkan", type=None)
    up_img  = st.file_uploader("🖼️ Upload gambar PNG sebagai carrier", type=["png"])

    if st.button("Proses Enkripsi + Sisipkan") and up_file and up_img and key_bytes:
        try:
            file_bytes = up_file.read()
            img_bytes  = up_img.read()

            # AES-256 CBC
            iv = os.urandom(16)
            iv_ct = aes256_cbc_encrypt(file_bytes, key_bytes, iv)

            # pastikan gambar cukup, resize otomatis bila tidak
            img = Image.open(io.BytesIO(img_bytes)).convert("RGB")
            w, h = img.size
            need_bits = (len(iv_ct) + 4) * 8
            while w*h*3 < need_bits:
                w *= 2; h *= 2
                img = img.resize((w, h), Image.Resampling.LANCZOS)
                st.warning(f"Gambar di-resize ke {w}×{h} agar muat payload.")

            buf = io.BytesIO()
            img.save(buf, format="PNG")
            resized_bytes = buf.getvalue()

            stego_png = encode_file_to_image(iv_ct, resized_bytes)
            st.success("Berhasil! Unduh gambar stego di bawah ini.")
            st.download_button("⬇️ Download stego_output.png", data=stego_png,
                               file_name="stego_output.png", mime="image/png")
        except Exception as e:
            st.error(f"Gagal: {e}")

elif mode == "Ekstraksi + Dekripsi":
    st.info("Harap unduh file hasil sesuai dengan format aslinya agar tetap dapat dibuka dan digunakan tanpa mengalami perubahan maupun kerusakan.")
    up_stego = st.file_uploader("🖼️ Upload gambar stego (PNG)", type=["png"])
    selected_ext = st.selectbox("Ekstensi file keluaran:", [".pdf",".docx",".xlsx",".xls",".pptx",".png",".jpg",".txt",".zip",".bin"])

    if st.button("Proses Ekstraksi + Dekripsi") and up_stego and key_bytes:
        try:
            stego_bytes = up_stego.read()
            iv_ct = decode_file_from_image(stego_bytes)
            plain = aes256_cbc_decrypt(iv_ct, key_bytes)

            st.success("Berhasil diekstrak & didekripsi.")
            st.download_button(f"⬇️ Download output{selected_ext}", data=plain,
                               file_name=f"output{selected_ext}", mime="application/octet-stream")
        except Exception as e:
            st.error(f"Gagal: {e}")

st.markdown("---")

# Tombol keluar
st.write(
    "Terima kasih telah menggunakan website ini, semoga bermanfaat. "
    "Tekan tombol berikut untuk mengakhirinya:"
)

if st.button("🔚 Keluar"):
    st.success("Sampai jumpa")
    st.link_button('https://www.google.com/?hl=id')
