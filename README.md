# Asesor Keamanan Email Komprehensif

Sebuah skrip Python `all-in-one` untuk melakukan asesmen mendalam terhadap postur keamanan email suatu domain. Alat ini memeriksa konfigurasi fundamental seperti SPF, DKIM, DMARC, keamanan transport (TLS), dan reputasi IP, serta mampu mendeteksi miskonfigurasi umum pada DNS.

## Fitur Utama

-   **Pemeriksaan Autentikasi:** Validasi mendalam terhadap record SPF, DKIM, dan DMARC, termasuk penanganan pewarisan (inheritance) pada subdomain.
-   **Validasi Keamanan Transport:** Memeriksa dukungan STARTTLS pada server email dan menangani berbagai skenario sertifikat SSL/TLS, termasuk *hostname mismatch* pada provider besar.
-   **Pemeriksaan Reputasi:** Mengecek alamat IP server email terhadap beberapa DNS Blacklist (DNSBL) terkemuka.
-   **Deteksi Konfigurasi Tidak Standar:** Secara proaktif mendeteksi dan melaporkan konfigurasi DNS yang tidak sesuai standar RFC (misalnya, MX record yang menunjuk langsung ke IP) sebagai **temuan kritis**.
-   **Laporan Terstruktur:** Menghasilkan laporan yang mudah dibaca di terminal dengan kode warna untuk status baik, peringatan, dan buruk.

---

## Prasyarat

Sebelum menjalankan skrip, pastikan Anda memiliki:

-   **Python 3.8+**
-   Manajer paket **pip** untuk Python 3.
-   Koneksi internet yang tidak memblokir port **53 (DNS)** dan **25 (SMTP)**.

---

## Instalasi

1.  **Clone repositori ini:**
    ```bash
    git clone [https://github.com/nama-anda/nama-repositori-anda.git](https://github.com/nama-anda/nama-repositori-anda.git)
    cd nama-repositori-anda
    ```

2.  **Buat dan aktifkan lingkungan virtual (direkomendasikan):**
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    # Untuk Windows, gunakan: venv\Scripts\activate
    ```

3.  **Install semua dependensi yang dibutuhkan:**
    Buat file bernama `requirements.txt` dan isi dengan teks berikut:
    ```
    dnspython
    requests
    colorama
    certifi
    ipaddress
    ```
    Kemudian install dengan perintah:
    ```bash
    python3 -m pip install -r requirements.txt
    ```

---

## Cara Penggunaan

Jalankan skrip dari terminal dengan memberikan nama domain yang ingin diasesmen menggunakan argumen `-d` atau `--domain`.

```bash
python3 email_assessor_final.py -d <domain_target>
```

**Contoh:**
```bash
python3 email_assessor_final.py -d hin0.co.id
```
```bash
python3 email_assessor_final.py --domain google.com
```

---

## Contoh Hasil Laporan

Berikut adalah contoh output saat skrip mendeteksi miskonfigurasi kritis pada MX record:

```
Mulai Asesmen Keamanan Email untuk Domain: hin0.co.id

=============== TEMUAN KRITIS: Konfigurasi MX Record Tidak Standar ===============
[-] [Temuan]: MX Record untuk domain 'hin0.co.id' menunjuk langsung ke alamat IP (103.93.160.39), bukan ke hostname.

[!] [Risiko/Dampak]:
[!]   1. Pelanggaran Standar RFC 5321: Menyebabkan masalah interoperabilitas dengan server email lain.
[!]   2. Masalah Pengiriman Email: Banyak server besar dapat menolak atau menandai email sebagai spam.
[!]   3. Kegagalan Validasi Keamanan: Protokol seperti TLS/SSL kesulitan memverifikasi sertifikat.
[!]   4. Manajemen Tidak Fleksibel: Sulit untuk mengubah IP server atau melakukan load balancing.

[+] [Rekomendasi Perbaikan (Langkah Selanjutnya)]:
[+]   1. Buat A record baru di DNS Anda untuk mengarahkan sebuah hostname ke IP server Anda.
[+]      Contoh: Buat A record 'mail.hin0.co.id' yang menunjuk ke '103.93.160.39'.
[+]   2. Ubah MX record Anda agar menunjuk ke hostname yang baru dibuat tersebut.
[+]      Contoh: Ubah MX record untuk 'hin0.co.id' agar menunjuk ke 'mail.hin0.co.id'.

=============== Modul 1: Penilaian Autentikasi ===============

=============== Modul 1.1: Pemeriksaan SPF ===============
[+] SPF record ditemukan: v=spf1 a mx ip4:103.93.160.39 ip4:103.44.27.166 ~all
[!] Kebijakan SPF adalah ~all (SoftFail). Sebaiknya gunakan -all (Fail).

... (sisa laporan) ...
```

---

## Penjelasan Modul Pemeriksaan

-   **Temuan Kritis:** Bagian ini hanya muncul jika skrip mendeteksi masalah fundamental pada konfigurasi DNS yang dapat memengaruhi semua aspek keamanan email.
-   **SPF (Sender Policy Framework):** Memeriksa apakah ada daftar server yang diizinkan untuk mengirim email atas nama domain Anda, untuk mencegah *spoofing*.
-   **DKIM (DomainKeys Identified Mail):** Mencari tanda tangan digital yang membuktikan bahwa isi email tidak diubah selama transit.
-   **DMARC (Domain-based Message Authentication, Reporting, and Conformance):** Memeriksa kebijakan yang memberitahu server penerima apa yang harus dilakukan jika email gagal pemeriksaan SPF atau DKIM.
-   **TLS (Transport Layer Security):** Memastikan jalur komunikasi antara server email dienkripsi untuk mencegah penyadapan.
-   **DNSBL (DNS Blacklist):** Memeriksa apakah alamat IP server email Anda memiliki reputasi buruk dan terdaftar sebagai sumber spam.

---

## Kontribusi

Kontribusi sangat diterima! Silakan buat *pull request* untuk menambahkan fitur atau perbaikan, atau buka *issue* untuk melaporkan bug.

---

## Lisensi

Proyek ini dilisensikan di bawah [Lisensi MIT](LICENSE).
