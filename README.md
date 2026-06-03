# SignDoc — Aplikasi Tanda Tangan Digital

Proyek UAS Kriptografi — Program Studi Informatika

SignDoc adalah aplikasi web tanda tangan digital berbasis Flask yang memungkinkan pengguna mengunggah dokumen, menandatanganinya secara digital menggunakan kriptografi asimetris RSA-2048, mengundang pengguna lain untuk ikut menandatangani, serta memverifikasi keaslian dokumen dan tanda tangan.

---

## Teknologi & Algoritma Kriptografi

| Komponen | Algoritma |
|----------|-----------|
| Hash dokumen | SHA-256 |
| Tanda tangan digital | RSA-2048 dengan padding PSS |
| Enkripsi kunci privat | AES-256-CBC |
| Derivasi kunci dari password | PBKDF2-HMAC-SHA256 (100.000 iterasi) |
| Hash password login | bcrypt (Werkzeug) |

---

## Fitur

- Registrasi akun dengan generate RSA-2048 keypair otomatis
- Kunci privat dienkripsi AES-256 menggunakan password user — tidak pernah disimpan plain
- Upload dokumen (PDF) dengan hashing SHA-256 otomatis
- Tanda tangan dokumen menggunakan kunci privat user (RSA-PSS)
- Multi-signer — satu dokumen bisa ditandatangani oleh banyak pengguna
- Sistem undangan penandatangan — pemilik dokumen bisa mengundang user lain
- Deteksi integritas dokumen — notifikasi jika file berubah setelah diupload
- Verifikasi tanda tangan via Signature ID
- Verifikasi tanda tangan via upload file dokumen + file .sig + file public key .pem
- Verifikasi publik via scan QR Code tanpa perlu login
- Riwayat tanda tangan per user
- Export laporan verifikasi ke PDF
- Download dokumen bertanda tangan dengan stamp QR digital
- Download file signature (.sig) dan public key (.pem)

---

## Struktur Proyek

```
signdoc/
├── app.py                  # Entry point Flask
├── extensions.py           # Inisialisasi db dan login manager
├── models.py               # Model database (User, Document, Signature, Invitation)
├── crypto_utils.py         # Semua fungsi kriptografi
├── requirements.txt
├── .env                    # SECRET_KEY (tidak di-commit)
├── routes/
│   ├── auth.py             # Register, login, logout
│   ├── documents.py        # Upload, sign, invite, download, export
│   └── verify.py           # Verifikasi signature dan QR
├── templates/              # HTML templates (Jinja2)
├── static/
│   └── qrcodes/            # QR code yang digenerate
└── uploads/                # File dokumen yang diupload
```

---

## Cara Menjalankan

**1. Clone repo**
```bash
git clone https://github.com/studychannn/Rizkey-Signdoc.git
cd Rizkey-Signdoc
```

**2. Buat virtual environment**
```bash
python -m venv venv
venv\Scripts\activate        # Windows
# atau
source venv/bin/activate     # Mac/Linux
```

**3. Install dependencies**
```bash
pip install -r requirements.txt
```

**4. Buat file .env**

Buat file `.env` di folder `signdoc/` dengan isi:
```
SECRET_KEY=isi_dengan_string_acak_yang_panjang
```

**5. Jalankan aplikasi**
```bash
python app.py
```

Buka browser: `http://localhost:5000`

---

## Alur Penggunaan

1. **Register** — sistem otomatis generate RSA-2048 keypair, kunci privat langsung dienkripsi AES-256
2. **Login** — autentikasi via bcrypt hash
3. **Upload dokumen** — sistem hitung hash SHA-256 dan generate QR code verifikasi
4. **Tanda tangan** — input password untuk dekripsi kunci privat, lalu sign hash dokumen dengan RSA-PSS
5. **Undang penandatangan lain** — kirim undangan ke username lain, mereka bisa tanda tangan dengan kunci privat mereka sendiri
6. **Verifikasi** — bisa via Signature ID, upload file, atau scan QR Code

---

## Dependencies

```
Flask >= 3.1.0
Flask-SQLAlchemy >= 3.1.1
Flask-Login >= 0.6.3
cryptography >= 42.0.0
Werkzeug >= 3.1.0
qrcode[pil] >= 7.4.0
reportlab >= 4.2.0
Pillow >= 10.0.0
pypdf >= 4.0.0
```

---

Dibuat untuk memenuhi tugas UAS mata kuliah Kriptografi Modern.
