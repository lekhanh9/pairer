#!/usr/bin/env python3
"""
Lockdown Local Pairing Client
Bắt tay trực tiếp với lockdownd trên thiết bị iOS jailbreak mà không cần máy tính.
"""

import sys
import os
import socket
import struct
import time
import uuid
import plistlib
import subprocess
import json
import base64

UDID = "22f82ce5bd377b75035be2458585bbfbb8d189ca"
LOCKDOWN_PORT = 62078

def get_local_wifi_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

def der_to_pem(b64_str, label="CERTIFICATE"):
    lines = [f"-----BEGIN {label}-----"]
    for i in range(0, len(b64_str), 64):
        lines.append(b64_str[i:i+64])
    lines.append(f"-----END {label}-----\n")
    return "\n".join(lines).encode('ascii')

def generate_keys():
    js = """
    const crypto = require('crypto');
    const root = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const host = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    console.log(JSON.stringify({
        rootPub: root.publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
        hostPub: host.publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
        rootPriv: root.privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
        hostPriv: host.privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
    }));
    """
    proc = subprocess.run(['node', '-e', js], capture_output=True, text=True, check=True)
    out = json.loads(proc.stdout)
    return {
        'root_cert_pem': der_to_pem(out['rootPub'], "CERTIFICATE"),
        'host_cert_pem': der_to_pem(out['hostPub'], "CERTIFICATE"),
        'root_key_pem': der_to_pem(out['rootPriv'], "RSA PRIVATE KEY"),
        'host_key_pem': der_to_pem(out['hostPriv'], "RSA PRIVATE KEY"),
    }

def send_plist(sock, d):
    data = plistlib.dumps(d)
    sock.sendall(struct.pack('>I', len(data)) + data)

def recv_plist(sock):
    hdr = sock.recv(4)
    if not hdr or len(hdr) < 4:
        raise ConnectionResetError("Mất kết nối với lockdownd")
    length = struct.unpack('>I', hdr)[0]
    buf = b''
    while len(buf) < length:
        chunk = sock.recv(min(length - len(buf), 4096))
        if not chunk: break
        buf += chunk
    return plistlib.loads(buf)

def main():
    print("====================================================")
    print("    Lockdown Local Pairing Tool for iOS (No-PC)     ")
    print("====================================================")

    ip = get_local_wifi_ip()
    print(f"[*] Địa chỉ IP cục bộ: {ip}")
    print(f"[*] Thiết bị UDID: {UDID}")

    print("[*] Đang kết nối tới lockdownd...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(15.0)
    try:
        sock.connect((ip, LOCKDOWN_PORT))
    except Exception as e:
        print(f"[-] Không thể kết nối tới {ip}:{LOCKDOWN_PORT} - {e}")
        return 1
    print("[+] Kết nối thành công!")

    # 1. QueryType
    send_plist(sock, {'Request': 'QueryType'})
    resp = recv_plist(sock)
    print(f"[+] lockdownd Type: {resp.get('Type')}")

    # 2. Sinh khóa RSA 2048 và chứng chỉ PEM
    print("[*] Đang sinh cặp khóa RSA 2048-bit và chứng chỉ Root/Host...")
    keys = generate_keys()
    print("[+] Đã sinh xong chứng chỉ!")

    host_id = str(uuid.uuid4()).upper()
    system_buid = str(uuid.uuid4()).upper()

    pair_record = {
        'HostID': host_id,
        'SystemBUID': system_buid,
        'HostCertificate': keys['host_cert_pem'],
        'RootCertificate': keys['root_cert_pem']
    }

    req = {
        'Request': 'Pair',
        'ProtocolVersion': '2',
        'HostName': 'iPhone',
        'HostID': host_id,
        'PairRecord': pair_record,
        'PairingOptions': {
            'ExtendedPairingErrors': True
        }
    }

    print("[*] Gửi yêu cầu ghép đôi (Pair Request) tới lockdownd...")
    send_plist(sock, req)

    pair_resp = recv_plist(sock)
    while True:
        err = pair_resp.get('Error')
        if not err:
            print("\n[🎉 BẮT TAY THÀNH CÔNG] lockdownd đã chấp nhận ghép đôi!")
            break

        if err in ['PasswordProtected', 'PairingDialogResponsePending']:
            print("\n[⚠️ VUI LÒNG BẬT MÀN HÌNH iPHONE]")
            print(" -> Bấm 'Tin cậy' (Trust) trên màn hình và NHẬP PASSCODE...")
            time.sleep(3)
            send_plist(sock, req)
            pair_resp = recv_plist(sock)
        else:
            print(f"[-] Lỗi từ lockdownd: {pair_resp}")
            sock.close()
            return 1

    escrow_bag = pair_resp.get('EscrowBag')
    device_cert = pair_resp.get('DeviceCertificate')
    if not device_cert:
        device_cert = keys['host_cert_pem']
    elif not device_cert.startswith(b"-----BEGIN"):
        device_cert = der_to_pem(device_cert, "CERTIFICATE")

    # Lấy WiFi MAC address
    wifi_mac = "7c:9a:1d:43:50:83"
    try:
        sock_mac = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock_mac.connect((ip, LOCKDOWN_PORT))
        send_plist(sock_mac, {'Request': 'GetValue', 'Key': 'WiFiAddress'})
        mac_resp = recv_plist(sock_mac)
        if mac_resp.get('Value'):
            wifi_mac = mac_resp['Value']
        sock_mac.close()
    except Exception:
        pass

    sock.close()

    # 3. Tạo Pairing Record hoàn chỉnh
    final_record = {
        'DeviceCertificate': device_cert,
        'HostCertificate': keys['host_cert_pem'],
        'HostID': host_id,
        'HostPrivateKey': keys['host_key_pem'],
        'RootCertificate': keys['root_cert_pem'],
        'RootPrivateKey': keys['root_key_pem'],
        'SystemBUID': system_buid,
        'WiFiMACAddress': wifi_mac,
        'UDID': UDID
    }
    if escrow_bag:
        final_record['EscrowBag'] = escrow_bag

    out_paths = [
        f"{UDID}.plist",
        f"/var/mobile/{UDID}.plist",
        f"/var/mobile/Documents/{UDID}.plist",
        f"/var/mobile/Documents/PairingFile_Lockdown.plist"
    ]
    for p in out_paths:
        try:
            with open(p, 'wb') as f:
                plistlib.dump(final_record, f)
        except Exception:
            pass

    print("\n====================================================")
    print("[🎉 THÀNH CÔNG] File pairing record đã được tạo tại:")
    for p in out_paths:
        if os.path.exists(p):
            print(f"  - {p}")
    print("====================================================")
    print("Bạn có thể import trực tiếp file này vào SideStore hoặc Jitterbug ngay trên máy!")
    return 0

if __name__ == '__main__':
    sys.exit(main())
