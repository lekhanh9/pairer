# Lockdown Local Pairing Tweak & Generator

Dự án này cho phép **tạo Pairing Record (.plist) 100% trên thiết bị iOS jailbreak mà không cần máy tính**, hoạt động bằng cách:
1. **Hook `lockdownd`**: Đánh lừa daemon `lockdownd` rằng kết nối mạng cục bộ (`127.0.0.1` / Wi-Fi) là kết nối qua cáp **USB** (Transport Type = 1).
2. **Client Script (`pair_local.py`)**: Kết nối tới `127.0.0.1:62078`, gửi request `Pair`, trigger popup "Tin cậy thiết bị này" trên màn hình và xuất file `<UDID>.plist` hoàn chỉnh kèm `HostPrivateKey`.

---

## 1. Cơ chế kỹ thuật (Reverse Engineering lockdownd trên iOS 16)
Khi nhận bản tin `Request: Pair`, `lockdownd` kiểm tra loại kết nối bằng hàm:
```c
int get_transport_type(void *conn) {
    if (!conn) return 4;
    return *(uint32_t *)((uintptr_t)conn + 0x10);
}
```
* **Giá trị trả về:**
  * `1`: USB
  * `2` hoặc `3`: Wi-Fi / Local Network / Loopback
  * `4`: Invalid

* **Điểm kiểm tra của iOS:**
  * Tại địa chỉ kiểm tra của `handle_pair`, nếu `transport_type != 1`, `lockdownd` sẽ nhảy thẳng tới nhánh lỗi và trả về: `PairingProhibitedOverThisConnection`.
  * Tại bộ điều phối trước `handle_pair`, nếu `transport_type == 3`, nó ép sang giao thức `PairCU` (CoreUtils SRP) thay vì cho phép `Pair` truyền thống.

* **Giải pháp của Tweak:**
  Hook hàm `get_transport_type` (nhận diện bằng pattern độc nhất `60 00 00 b4 00 10 40 b9 c0 03 5f d6 80 00 80 52 c0 03 5f d6`), nếu kết nối là `2` hoặc `3`, ép trả về `1` (USB).

---

## 2. Các file trong thư mục này
* `Tweak.m`: Mã nguồn dylib inject vào `lockdownd`.
* `LockdownPairing.plist`: Filter của tweak (`executables = ("lockdownd")`).
* `pair_local.py`: Script Python cục bộ thực hiện bắt tay và xuất file pairing.
