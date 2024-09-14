import os
import psutil
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# String kunci privat dalam format PEM (gunakan kunci privat Anda di sini)
PRIVATE_KEY_PEM = b"""
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDG6T1/WzQjLAcB
MH1D82ZGfxR5F6DZO/gzYFfxQmqSrASa2lwsbcVauhA8KK1oj7UChBc8lDgIm/uN
p+VNg3riq8Q5N9KnMd0Yy5RcEVSkZAWJRjRdd66wHAwvV8pUndMQD30kYNlLPF7N
sCvp3L09Dt1I
-----END PRIVATE KEY-----
"""

# Fungsi untuk memuat kunci privat dari string PEM
def load_private_key():
    private_key = serialization.load_pem_private_key(
        PRIVATE_KEY_PEM,
        password=None,  # Atur password jika kunci privat Anda terenkripsi
        backend=default_backend()
    )
    return private_key

# Fungsi untuk mendekripsi satu file
def decrypt_file(private_key, file_path):
    try:
        with open(file_path, 'rb') as f:
            iv = f.read(12)  # Baca IV
            encrypted_aes_key = f.read(256)  # Baca kunci AES yang terenkripsi (ukuran tergantung pada panjang kunci RSA)
            tag = f.read(16)  # Baca tag
            ciphertext = f.read()  # Baca ciphertext

        # Dekripsi AES key dengan kunci privat RSA
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Dekripsi data menggunakan AES-GCM
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Simpan hasil dekripsi ke file baru tanpa ekstensi .K1NP1NG
        decrypted_file_path = file_path.replace('.K1NP1NG', '')
        with open(decrypted_file_path, 'wb') as f_out:
            f_out.write(plaintext)

        # Hapus file terenkripsi
        os.remove(file_path)

        return True, f"{file_path} berhasil didekripsi menjadi {decrypted_file_path}"

    except Exception as e:
        return False, f"Gagal mendekripsi {file_path}: {e}"

# Fungsi untuk mendekripsi semua partisi yang terdeteksi
def decrypt_partitions():
    private_key = load_private_key()

    # Ambil semua partisi yang terpasang
    partitions = psutil.disk_partitions()

    for partition in partitions:
        # Abaikan partisi sistem atau yang tidak valid
        if 'system' in partition.opts or partition.fstype == '':
            continue

        # Dekripsi semua file dengan ekstensi .K1NP1NG di partisi yang relevan
        for root, _, files in os.walk(partition.mountpoint):
            for file in files:
                if file.endswith('.K1NP1NG'):  # Hanya dekripsi file dengan ekstensi .K1NP1NG
                    file_path = os.path.join(root, file)
                    success, message = decrypt_file(private_key, file_path)
                    print(message)


if __name__ == "__main__":
    decrypt_partitions()
