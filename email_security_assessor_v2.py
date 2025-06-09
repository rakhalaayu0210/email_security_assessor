import dns.resolver
import socket
import ssl
import requests
import argparse
import ipaddress
import certifi
from colorama import init, Fore, Style

# Inisialisasi Colorama
init(autoreset=True)

# --- Fungsi Pembantu untuk Output Berwarna ---
def print_good(text):
    print(f"{Fore.GREEN}[+] {text}{Style.RESET_ALL}")

def print_bad(text):
    print(f"{Fore.RED}[-] {text}{Style.RESET_ALL}")

def print_warn(text):
    print(f"{Fore.YELLOW}[!] {text}{Style.RESET_ALL}")

def print_info(text):
    print(f"{Fore.CYAN}[*] {text}{Style.RESET_ALL}")

def print_header(text):
    print(f"\n{Fore.MAGENTA}{'='*15} {text} {'='*15}{Style.RESET_ALL}")

def is_ip_address(value):
    """Mendeteksi apakah sebuah string adalah alamat IP v4 atau v6."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

# --- Konfigurasi DNS Resolver Global ---
my_resolver = dns.resolver.Resolver()
my_resolver.nameservers = ['8.8.8.8', '1.1.1.1'] # Menggunakan DNS Google dan Cloudflare

# --- Fungsi Pemeriksaan ---

def check_mx_record_compliance(domain, mx_records):
    """Memeriksa kepatuhan MX record dan melaporkannya sebagai temuan jika tidak sesuai standar."""
    if not mx_records:
        return

    highest_priority_mx = mx_records[0]
    if is_ip_address(highest_priority_mx):
        print_header("TEMUAN KRITIS: Konfigurasi MX Record Tidak Standar")
        print_bad(f"[Temuan]: MX Record untuk domain '{domain}' menunjuk langsung ke alamat IP ({highest_priority_mx}), bukan ke hostname.")
        print_warn("\n[Risiko/Dampak]:")
        print_warn("  1. Pelanggaran Standar RFC 5321: Menyebabkan masalah interoperabilitas dengan server email lain.")
        print_warn("  2. Masalah Pengiriman Email: Banyak server besar dapat menolak atau menandai email sebagai spam.")
        print_warn("  3. Kegagalan Validasi Keamanan: Protokol seperti TLS/SSL kesulitan memverifikasi sertifikat.")
        print_warn("  4. Manajemen Tidak Fleksibel: Sulit untuk mengubah IP server atau melakukan load balancing.")
        print_good("\n[Rekomendasi Perbaikan (Langkah Selanjutnya)]:")
        print_good("  1. Buat A record baru di DNS Anda untuk mengarahkan sebuah hostname ke IP server Anda.")
        print_good(f"     Contoh: Buat A record 'mail.{domain}' yang menunjuk ke '{highest_priority_mx}'.")
        print_good("  2. Ubah MX record Anda agar menunjuk ke hostname yang baru dibuat tersebut.")
        print_good(f"     Contoh: Ubah MX record untuk '{domain}' agar menunjuk ke 'mail.{domain}'.")

def get_mx_records(domain):
    """Mendapatkan dan mengurutkan MX record untuk sebuah domain."""
    try:
        mx_answers = my_resolver.resolve(domain, 'MX')
        sorted_records = sorted(mx_answers, key=lambda r: r.preference)
        return [str(r.exchange).rstrip('.') for r in sorted_records]
    except Exception:
        return []

def check_spf(domain):
    """Memeriksa dan menganalisis SPF record."""
    print_header("Modul 1.1: Pemeriksaan SPF")
    try:
        txt_records = my_resolver.resolve(domain, 'TXT')
        spf_record = next((r.strings[0].decode() for r in txt_records if r.strings[0].decode().startswith('v=spf1')), None)
        if not spf_record:
            print_bad(f"Tidak ada SPF record ditemukan untuk {domain}")
            return
        print_good(f"SPF record ditemukan: {spf_record}")
        if '~all' in spf_record: print_warn("Kebijakan SPF adalah ~all (SoftFail). Sebaiknya gunakan -all (Fail).")
        elif '-all' in spf_record: print_good("Kebijakan SPF adalah -all (Fail). Ini adalah praktik terbaik.")
        elif '+all' in spf_record: print_bad("KRITIS: Kebijakan SPF adalah +all, mengizinkan siapa saja mengirim!")
        else: print_warn("Tidak ada mekanisme 'all' yang valid ditemukan.")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        print_bad(f"Tidak ada SPF record ditemukan untuk {domain}")
    except Exception as e: print_bad(f"Error saat memeriksa SPF: {e}")

def analyze_dmarc_policy(dmarc_record):
    """Fungsi pembantu untuk menganalisis kebijakan DMARC."""
    policy = next((s.strip() for s in dmarc_record.split(';') if 'p=' in s), None)
    if policy:
        if 'p=none' in policy: print_warn("Kebijakan DMARC adalah 'p=none' (mode monitoring).")
        elif 'p=quarantine' in policy: print_good("Kebijakan DMARC adalah 'p=quarantine'.")
        elif 'p=reject' in policy: print_good("SANGAT BAIK: Kebijakan DMARC adalah 'p=reject'.")
    else: print_bad("Tidak ada tag kebijakan 'p=' yang ditemukan.")
    rua = next((s.strip() for s in dmarc_record.split(';') if 'rua=' in s), None)
    if rua: print_good(f"Pelaporan agregat (rua) dikonfigurasi.")
    else: print_warn("Pelaporan agregat (rua) tidak dikonfigurasi.")

def check_dmarc(domain):
    """Memeriksa DMARC pada subdomain, dan jika gagal, memeriksa domain induknya."""
    print_header("Modul 1.3: Pemeriksaan DMARC")
    dmarc_domain = f"_dmarc.{domain}"
    try:
        txt_records = my_resolver.resolve(dmarc_domain, 'TXT')
        dmarc_record = txt_records[0].strings[0].decode()
        print_good(f"DMARC record ditemukan untuk {domain}: {dmarc_record}")
        analyze_dmarc_policy(dmarc_record)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        print_warn(f"Tidak ada DMARC record spesifik ditemukan di {dmarc_domain}.")
        if domain.count('.') > 1:
            parent_domain = '.'.join(domain.split('.')[1:])
            parent_dmarc_domain = f"_dmarc.{parent_domain}"
            print_info(f"Mencari kebijakan warisan di domain induk: {parent_dmarc_domain}")
            try:
                parent_txt_records = my_resolver.resolve(parent_dmarc_domain, 'TXT')
                parent_dmarc_record = parent_txt_records[0].strings[0].decode()
                print_good(f"Ditemukan kebijakan DMARC warisan dari {parent_domain}: {parent_dmarc_record}")
                analyze_dmarc_policy(parent_dmarc_record)
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                print_bad(f"Tidak ada DMARC record ditemukan baik untuk subdomain maupun domain induknya.")
        else:
            print_bad(f"Tidak ada DMARC record ditemukan untuk {domain}")
    except Exception as e: print_bad(f"Error saat memeriksa DMARC: {e}")

def check_dkim(domain, selectors):
    """Mencari DKIM record dengan mencoba beberapa selector umum secara tangguh."""
    print_header("Modul 1.2: Pemeriksaan DKIM")
    print_info(f"Mencoba menebak selector DKIM umum: {', '.join(selectors)}")
    found_selector = False
    for selector in selectors:
        dkim_domain = f"{selector}._domainkey.{domain}"
        try:
            my_resolver.resolve(dkim_domain, 'TXT')
            print_good(f"Selector DKIM ditemukan: '{selector}' di {dkim_domain}")
            found_selector = True
            break
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            continue
        except Exception as e:
            print_warn(f"Terjadi error saat memeriksa selector '{selector}': {e}")
    if not found_selector:
        print_warn("Tidak dapat menemukan DKIM record dengan selector umum yang dicoba.")

def check_tls(domain):
    """Memeriksa dukungan dan keamanan koneksi TLS."""
    print_header("Modul 2.1: Pemeriksaan Keamanan Transport (TLS)")
    mx_records = get_mx_records(domain)
    if not mx_records:
        print_bad(f"Tidak dapat menemukan MX record untuk {domain}")
        return
    mail_server = mx_records[0]
    print_info(f"Menguji server email prioritas utama: {mail_server}")

    hostname_for_ssl = domain
    if not is_ip_address(mail_server):
        hostname_for_ssl = mail_server

    context = ssl.create_default_context(cafile=certifi.where())
    try:
        with socket.create_connection((mail_server, 25), timeout=10) as sock:
            sock.recv(1024)
            sock.sendall(b'EHLO test.com\r\n')
            response = sock.recv(1024).decode()
            if 'STARTTLS' not in response:
                print_bad("Server email tidak mendukung STARTTLS.")
                return
            print_good("Server email mendukung STARTTLS.")
            sock.sendall(b'STARTTLS\r\n')
            sock.recv(1024)
            with context.wrap_socket(sock, server_hostname=hostname_for_ssl) as ssock:
                tls_version = ssock.version()
                print_good(f"Koneksi TLS berhasil dibuat dan terverifikasi. Versi: {tls_version}")
                if "TLSv1.3" not in tls_version: print_warn(f"Server tidak menggunakan TLS 1.3, versi paling aman.")
    except ssl.SSLCertVerificationError as e:
        if "Hostname mismatch" in str(e):
            print_warn(f"Koneksi terenkripsi, tetapi terjadi 'Hostname Mismatch'.")
            print_info("Ini umum pada provider besar atau jika sertifikat tidak cocok dengan hostname.")
        else:
            print_bad(f"Verifikasi sertifikat SSL gagal: {e}")
    except Exception as e:
        print_bad(f"Gagal terhubung atau melakukan negosiasi TLS dengan {mail_server}: {e}")

def check_dnsbl(domain):
    """Memeriksa reputasi IP server email pada beberapa blacklist utama."""
    print_header("Modul 3: Pemeriksaan Reputasi (DNSBL)")
    mx_records = get_mx_records(domain)
    if not mx_records:
        print_bad(f"Tidak dapat memeriksa DNSBL karena tidak ada MX record.")
        return
    mail_server = mx_records[0]
    try:
        mail_server_ip = mail_server if is_ip_address(mail_server) else socket.gethostbyname(mail_server)
    except socket.gaierror:
        print_bad(f"Tidak dapat menemukan alamat IP untuk mail server {mail_server}")
        return
    
    print_info(f"IP server email yang diuji adalah {mail_server_ip}")
    reversed_ip = '.'.join(reversed(mail_server_ip.split('.')))
    dnsbl_lists = ["zen.spamhaus.org", "bl.spamcop.net", "b.barracudacentral.org"]
    for dnsbl in dnsbl_lists:
        try:
            my_resolver.resolve(f"{reversed_ip}.{dnsbl}", 'A')
            print_bad(f"TERDAFTAR di {dnsbl}")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            print_good(f"Aman, tidak terdaftar di {dnsbl}")
        except Exception:
            print_warn(f"Gagal memeriksa {dnsbl}.")

def main():
    parser = argparse.ArgumentParser(description="Versi Final - Asesor Keamanan Email Komprehensif.")
    parser.add_argument("-d", "--domain", required=True, help="Domain yang akan dianalisis.")
    args = parser.parse_args()
    domain = args.domain
    
    print(f"\n{Fore.BLUE}{Style.BRIGHT}Mulai Asesmen Keamanan Email untuk Domain: {domain}{Style.RESET_ALL}")
    
    mx_records = get_mx_records(domain)
    
    # --- Pemeriksaan Kepatuhan MX Record ---
    check_mx_record_compliance(domain, mx_records)
    
    # Modul 1
    print_header("Modul 1: Penilaian Autentikasi")
    check_spf(domain)
    common_selectors = ['default', 'google', 'k1', 'k2', 'mandrill', 'dkim']
    check_dkim(domain, common_selectors)
    check_dmarc(domain)

    # Modul 2
    check_tls(domain)
    
    # Modul 3
    check_dnsbl(domain)
    
    print_header("Rekomendasi Tambahan")
    print_info("Untuk postur keamanan yang lebih kuat, pertimbangkan juga hal berikut:")
    print_good("Implementasi MTA-STS dan TLS-RPT untuk memaksa enkripsi.")
    print_good("Gunakan S/MIME atau PGP untuk enkripsi end-to-end pada email sensitif.")
    print_good("Lakukan pelatihan kesadaran phishing secara berkala kepada pengguna.")

    print(f"\n{Fore.BLUE}{Style.BRIGHT}Asesmen untuk {domain} selesai.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
