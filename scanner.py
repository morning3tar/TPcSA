import socket
import ssl
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from OpenSSL import crypto
import csv
import json
import requests
import urllib3
from cryptography.hazmat.primitives import serialization
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Helper Functions ---
def get_certificate(host, port):
    context = ssl.create_default_context()
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=host)
    conn.settimeout(5)
    try:
        conn.connect((host, port))
        der_cert = conn.getpeercert(True)
        pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)
        cert = x509.load_pem_x509_certificate(pem_cert.encode(), default_backend())
        return cert, pem_cert
    except Exception as e:
        return None, str(e)
    finally:
        conn.close()

def get_certificate_and_chain(host, port):
    context = ssl.create_default_context()
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=host)
    conn.settimeout(5)
    try:
        conn.connect((host, port))
        der_cert = conn.getpeercert(True)
        pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)
        cert = x509.load_pem_x509_certificate(pem_cert.encode(), default_backend())
        # Get chain (intermediates)
        chain = []
        for der in conn.get_peer_cert_chain()[1:] if hasattr(conn, 'get_peer_cert_chain') else []:
            pem = ssl.DER_cert_to_PEM_cert(der)
            chain.append(pem)
        return cert, pem_cert, chain
    except Exception as e:
        return None, str(e), []
    finally:
        conn.close()

def is_self_signed(cert):
    return cert.issuer == cert.subject

def hostname_matches(cert, hostname):
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = ext.value.get_values_for_type(x509.DNSName)
        if hostname in sans:
            return True
    except Exception:
        pass
    # fallback to CN
    cn = None
    for attr in cert.subject:
        if attr.oid.dotted_string == '2.5.4.3':  # CN
            cn = attr.value
            break
    return cn and (hostname == cn)

def check_ocsp_revocation(cert):
    # Basic OCSP check (best effort, not robust)
    try:
        aia = cert.extensions.get_extension_for_oid(x509.ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        ocsp_urls = [d.access_location.value for d in aia.value if d.access_method.dotted_string == '1.3.6.1.5.5.7.48.1']
        if not ocsp_urls:
            return 'No OCSP URL'
        return 'OCSP URL present'  # Full OCSP request/parse is complex
    except Exception:
        return 'No OCSP info'

def check_crl_revocation(cert):
    try:
        crl_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.CRL_DISTRIBUTION_POINTS)
        crl_urls = []
        for dp in crl_ext.value:
            for name in dp.full_name:
                crl_urls.append(name.value)
        if not crl_urls:
            return 'No CRL URL'
        return 'CRL URL present'  # Full CRL download/parse is complex
    except Exception:
        return 'No CRL info'

def get_supported_protocols_and_ciphers(host, port):
    protocols = {
        'TLSv1': ssl.PROTOCOL_TLSv1,
        'TLSv1_1': ssl.PROTOCOL_TLSv1_1,
        'TLSv1_2': ssl.PROTOCOL_TLSv1_2,
        'TLSv1_3': ssl.PROTOCOL_TLS_CLIENT  # Python 3.7+ uses TLS 1.3 by default
    }
    supported = []
    ciphers = set()
    for name, proto in protocols.items():
        try:
            context = ssl.SSLContext(proto)
            with socket.create_connection((host, port), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    supported.append(name)
                    ciphers.add(ssock.cipher()[0])
        except Exception:
            continue
    # Forward secrecy check (look for ECDHE/DHE ciphers)
    fs = any('DHE' in c for c in ciphers)
    return supported, list(ciphers), fs

def check_hsts_hpkp(host, port):
    url = f"https://{host}:{port}" if port != 443 else f"https://{host}"
    try:
        resp = requests.get(url, timeout=5, verify=False)
        hsts = resp.headers.get('Strict-Transport-Security', 'Not Set')
        hpkp = resp.headers.get('Public-Key-Pins', 'Not Set')
        return hsts, hpkp
    except Exception:
        return 'Error', 'Error'

def analyze_certificate(cert, pem_cert, host, chain, hostname):
    try:
        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
        not_before = cert.not_valid_before_utc.strftime('%Y-%m-%d')
        not_after = cert.not_valid_after_utc.strftime('%Y-%m-%d')
        days_left = (cert.not_valid_after_utc - datetime.now(timezone.utc)).days
        serial = hex(cert.serial_number)
        sig_algo = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else 'Unknown'
        pubkey = cert.public_key()
        pubkey_type = pubkey.__class__.__name__
        pubkey_size = getattr(pubkey, 'key_size', 'Unknown')
        san = []
        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            san = ext.value.get_values_for_type(x509.DNSName)
        except Exception:
            pass
        warnings = []
        if days_left < 0:
            warnings.append('Expired')
        elif days_left < 30:
            warnings.append('Expiring Soon')
        if pubkey_type == 'RSAPublicKey' and pubkey_size < 2048:
            warnings.append('Weak Key')
        if sig_algo in ['sha1', 'md5']:
            warnings.append('Weak Algorithm')
        if is_self_signed(cert):
            warnings.append('Self-signed')
        if not hostname_matches(cert, hostname.split(':')[0]):
            warnings.append('Hostname Mismatch')
        # Revocation
        ocsp_status = check_ocsp_revocation(cert)
        crl_status = check_crl_revocation(cert)
        # Protocols/ciphers
        supported_protocols, ciphers, forward_secrecy = get_supported_protocols_and_ciphers(hostname.split(':')[0], int(hostname.split(':')[1]) if ':' in hostname else 443)
        # HSTS/HPKP
        hsts, hpkp = check_hsts_hpkp(hostname.split(':')[0], int(hostname.split(':')[1]) if ':' in hostname else 443)
        return {
            'host': host,
            'expiry': not_after,
            'issuer': issuer,
            'algorithm': sig_algo,
            'warnings': ', '.join(warnings),
            'subject': subject,
            'serial': serial,
            'not_before': not_before,
            'not_after': not_after,
            'days_left': str(days_left),
            'pubkey_type': pubkey_type,
            'pubkey_size': str(pubkey_size),
            'san': ', '.join(san),
            'pem': pem_cert,
            'chain': chain,
            'ocsp': ocsp_status,
            'crl': crl_status,
            'protocols': ', '.join(supported_protocols),
            'ciphers': ', '.join(ciphers),
            'forward_secrecy': 'Yes' if forward_secrecy else 'No',
            'hsts': hsts,
            'hpkp': hpkp,
        }
    except Exception as e:
        return {
            'host': host,
            'expiry': 'Error',
            'issuer': 'Error',
            'algorithm': 'Error',
            'warnings': str(e),
            'subject': '',
            'serial': '',
            'not_before': '',
            'not_after': '',
            'days_left': '',
            'pubkey_type': '',
            'pubkey_size': '',
            'san': '',
            'pem': '',
            'chain': [],
            'ocsp': '',
            'crl': '',
            'protocols': '',
            'ciphers': '',
            'forward_secrecy': '',
            'hsts': '',
            'hpkp': '',
        }

def scan_targets(targets):
    results = []
    for target in targets:
        if ':' in target:
            host, port = target.split(':', 1)
            port = int(port)
        else:
            host, port = target, 443
        cert, pem_cert, chain = get_certificate_and_chain(host, port)
        if cert:
            result = analyze_certificate(cert, pem_cert, target, chain, host)
        else:
            result = {
                'host': target,
                'expiry': 'Error',
                'issuer': 'Error',
                'algorithm': 'Error',
                'warnings': pem_cert,
                'subject': '',
                'serial': '',
                'not_before': '',
                'not_after': '',
                'days_left': '',
                'pubkey_type': '',
                'pubkey_size': '',
                'san': '',
                'pem': '',
                'chain': [],
                'ocsp': '',
                'crl': '',
                'protocols': '',
                'ciphers': '',
                'forward_secrecy': '',
                'hsts': '',
                'hpkp': '',
            }
        results.append(result)
    return results

def export_results(results, path, fmt):
    if fmt == 'csv':
        with open(path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=results[0].keys())
            writer.writeheader()
            writer.writerows(results)
    elif fmt == 'json':
        with open(path, 'w') as f:
            json.dump(results, f, indent=2) 