# pairer (Lockdown Local Pairing)

A standalone iOS jailbreak tweak and native CLI tool to generate valid iOS pairing records (`<UDID>.plist`) directly on-device without requiring a computer, fully compatible with **SideStore**, **LiveContainer**, and **Jitterbug**.

## Features

- **No PC Required**: Handshakes with `lockdownd` over internal loopback (`127.0.0.1:62078`).
- **Cellular & Wi-Fi Independent**: Works over 4G/5G, Wi-Fi, or offline.
- **X.509 v3 Standard**: Generates standard OpenSSL certificates matching `libimobiledevice`.
- **Auto-Injection**: Automatically detects SideStore and LiveContainer app containers and copies `pairingFile.plist` directly into their `Documents/` directory without manual importing.
- **Universal Architecture**: Supports both `arm64` (A11 devices such as iPhone 8 Plus) and `arm64e` (A12+).
- **Supports Rootless and Roothide** jailbreaks.

## Installation

Install the `.deb` package via **Sileo**, **Zebra**, or **Filza**:
```bash
dpkg -i com.lockdown.localpairing_1.0.0_iphoneos-arm64e.deb
```

## Usage

### Pairing
Simply run in any terminal (NewTerm, Filza Terminal, or SSH):
```bash
pair-local
# or
idevicepair
```

The tool will:
1. Connect to `lockdownd`
2. Fetch device information (`UDID`, `WiFiAddress`, `DevicePublicKey`)
3. Generate RSA 2048-bit keys and X.509 v3 certificates
4. Execute `Pair` request and obtain `EscrowBag`
5. Generate the complete 10-field `<UDID>.plist`
6. Automatically inject `pairingFile.plist` into SideStore/LiveContainer containers

### Security Toggle (On / Off / Status)
To protect system security and restore stock Apple `lockdownd` behavior when not pairing:
```bash
pair-local off     # Disables the tweak hook, restoring 100% vanilla lockdownd security
pair-local on      # Re-enables the tweak hook for pairing
pair-local status  # Checks current hook status
```
Alternatively, toggle it anytime from **Settings ▸ Lockdown Pairing**.

## License

MIT License.
