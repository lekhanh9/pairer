#!/bin/sh
set -eu
: "${APELIN_PACKAGE_DIR:?run this through apelin_project_build}"
: "${APELIN_PROJECT_ROOT:?}" "${APELIN_BOOTSTRAP:?}" "${APELIN_ARCHITECTURE:?}"
: "${APELIN_BUILD_ID:?}" "${TMPDIR:?}"
: "${APELIN_PREFIX?}" # set, and empty on roothide

stage="$(mktemp -d "${TMPDIR:?}stage.XXXXXX")"
trap 'rm -rf -- "${stage:?}"' EXIT

if [ "$APELIN_BOOTSTRAP" = "roothide" ]; then
    TARGET_ARCH="arm64e"
    CLANG_TARGET="arm64-apple-ios16.0"
else
    TARGET_ARCH="arm64"
    CLANG_TARGET="arm64-apple-ios14.0"
fi

echo "[*] Building LockdownPairing for $APELIN_BOOTSTRAP ($TARGET_ARCH)..."

mkdir -p "$TMPDIR/build"

# 1. Compile Tweak Dylib
clang -target "$CLANG_TARGET" -shared -dynamiclib -O2 -Wall \
    -DAPELIN_BUILD_ID="\"$APELIN_BUILD_ID\"" \
    -framework Foundation -framework Security \
    "$APELIN_PROJECT_ROOT/LockdownPairing/Tweak.m" \
    -o "$TMPDIR/build/LockdownPairing.dylib"

ldid -S "$TMPDIR/build/LockdownPairing.dylib"

# 2. Compile Native C Pairing Tool (pair-local)
clang -target arm64-apple-ios16.0 -O2 -Wall \
    -DAPELIN_BUILD_ID="\"$APELIN_BUILD_ID\"" \
    -framework Foundation \
    "$APELIN_PROJECT_ROOT/LockdownPairing/pair_local.m" \
    -o "$TMPDIR/build/pair-local"

ldid -S"$APELIN_PROJECT_ROOT/LockdownPairing/Tool.entitlements" "$TMPDIR/build/pair-local"

tweak_dir="$stage$APELIN_PREFIX/Library/MobileSubstrate/DynamicLibraries"
bin_dir="$stage$APELIN_PREFIX/usr/bin"
debian_dir="$stage/DEBIAN"

mkdir -p "$tweak_dir" "$bin_dir" "$debian_dir"

cp "$TMPDIR/build/LockdownPairing.dylib" "$tweak_dir/LockdownPairing.dylib"
cp "$APELIN_PROJECT_ROOT/LockdownPairing/LockdownPairing.plist" "$tweak_dir/LockdownPairing.plist"

if [ "$APELIN_BOOTSTRAP" = "roothide" ]; then
    ln -s /usr/lib/DynamicPatches/AutoPatches.dylib "$tweak_dir/LockdownPairing.dylib.roothidepatch"
fi

cp "$TMPDIR/build/pair-local" "$bin_dir/pair-local"
chmod 755 "$bin_dir/pair-local"
ln -s pair-local "$bin_dir/idevicepair"

cat << EOF > "$debian_dir/control"
Package: com.lockdown.localpairing
Name: Lockdown Local Pairing
Version: 1.0.0
Architecture: $APELIN_ARCHITECTURE
Description: Pair iOS locally without a computer for SideStore and Jitterbug
Maintainer: Developer
Author: Developer
Section: Tweaks
Depends: mobilesubstrate, ellekit
EOF

cat << 'EOF' > "$debian_dir/postinst"
#!/bin/sh
set -e
killall -9 lockdownd 2>/dev/null || true
echo "Lockdown Local Pairing installed! Run 'pair-local' or 'idevicepair' in terminal to generate pairing file."
exit 0
EOF
chmod 755 "$debian_dir/postinst"

cat << 'EOF' > "$debian_dir/postrm"
#!/bin/sh
set -e
killall -9 lockdownd 2>/dev/null || true
exit 0
EOF
chmod 755 "$debian_dir/postrm"

dpkg-deb -b --root-owner-group "$stage" "$APELIN_PACKAGE_DIR/"
echo "[+] Package built successfully in $APELIN_PACKAGE_DIR!"
