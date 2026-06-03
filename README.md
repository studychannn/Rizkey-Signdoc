# SignDoc — Aplikasi Tanda Tangan Digital

Proyek Akhir Kriptografi Modern — Program Studi Informatika

## Cara Menjalankan

```bash
# Install dependencies
pip install -r requirements.txt

# Jalankan aplikasi
python app.py
```

Buka browser: http://localhost:5000

## Fitur

**Wajib:**
- Registrasi + generate RSA-2048 atau ECDSA P-256 key pair
- Kunci privat dienkripsi AES-256 dengan password user
- Upload dokumen (PDF, TXT, DOCX, PNG, JPG) + hash SHA-256
- Tanda tangani dokumen dengan kunci privat
- Verifikasi tanda tangan (VALID/INVALID + detail)
- Riwayat dokumen per user

**Pengembangan:**
- Multi-signer — satu dokumen bisa ditandatangani banyak pihak
- QR Code verifikasi cepat tanpa login
- Notifikasi dokumen dimodifikasi (deteksi hash berubah)
- Export laporan verifikasi PDF
