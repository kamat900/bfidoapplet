# Đăng nhập Ubuntu bằng vân tay FIDO2 (BMC S-USB)

Hướng dẫn thiết lập **đăng nhập / mở khoá màn hình Ubuntu bằng vân tay** trên thiết bị bảo mật
**BMC S-USB AIO** (USB VID `0x1FC9` / PID `0x0117`) — một FIDO2/CTAP2.1 authenticator có cảm biến vân tay.

> ⚠️ **ĐỌC TRƯỚC — chống tự khoá máy**
> - Cấu hình này là **passwordless**: *khi có khoá + vân tay đúng* thì vào thẳng, không cần mật khẩu.
>   Nhưng **mật khẩu vẫn được giữ làm phương án dự phòng** — KHÔNG bao giờ gỡ nó đi.
> - Luôn mở sẵn **một terminal `root`** (hoặc màn hình TTY `Ctrl+Alt+F3`) trước khi sửa file PAM.
> - **Nên đăng ký thêm một khoá/vân tay dự phòng** để không bị khoá ngoài nếu mất khoá chính.

Môi trường áp dụng: **Ubuntu (GNOME + GDM3)** — cả đăng nhập và mở khoá màn hình dùng chung service `gdm-password`.

---

## 1. Cài gói cần thiết

```bash
sudo apt update
sudo apt install -y libpam-u2f fido2-tools pamtester
```

Kiểm tra thiết bị được nhận:
```bash
fido2-token -L
# Kỳ vọng: /dev/hidrawX: vendor=0x1fc9, product=0x0117 (BMC S-USB AIO ...)
```

---

## 2. Đặt PIN và đăng ký vân tay lên thiết bị

Thiết bị yêu cầu **đặt PIN trước**, rồi mới đăng ký vân tay. Cách dễ nhất là dùng **Google Chrome**:

1. Mở `chrome://settings/securityKeys` → **Create a PIN** để đặt PIN cho thiết bị.
2. Vào mục **Fingerprints** (quản lý vân tay) → **Add** → chạm cảm biến **4 lần** cho tới khi đủ 100%.

> Có thể enroll bằng bất kỳ trang WebAuthn nào hỗ trợ quản lý authenticator (ví dụ `webauthn.io`,
> `token2.com`). Sau khi enroll xong, **rút và cắm lại thiết bị** một lần để trình duyệt/hệ thống nhận
> trạng thái mới.

Kiểm tra đã có vân tay:
```bash
fido2-token -I /dev/hidraw4   # thay X cho đúng thiết bị ở bước 1
# Kỳ vọng: options có "uv", "bioEnroll"; "uv modality: fingerprint"
```

---

## 3. Đăng ký credential đăng nhập vào PAM

Tạo file ánh xạ **trung tâm** `/etc/u2f_keys` (thư mục login đọc được lúc chưa vào phiên người dùng).
Dùng `--user-verification` để bắt buộc **vân tay**:

```bash
pamu2fcfg --user-verification -u "$USER" | sudo tee /etc/u2f_keys
sudo chmod 644 /etc/u2f_keys
sudo chown root:root /etc/u2f_keys
```
(Chạm/verify vân tay khi được nhắc. Dòng ghi vào sẽ có thuộc tính `+presence+verification`.)

### (Khuyến nghị) Đăng ký khoá/vân tay dự phòng
```bash
pamu2fcfg --user-verification -n     # in ra chuỗi bắt đầu bằng ":"
```
Copy chuỗi đó, mở `sudo nano /etc/u2f_keys`, **dán vào cuối dòng của user** (cùng một dòng, nối tiếp bằng
dấu `:`). Có nhiều credential ⇒ mất một cái vẫn còn cái kia.

---

## 4. Test an toàn bằng pamtester (chưa đụng đăng nhập thật)

```bash
sudo tee /etc/pam.d/u2ftest >/dev/null <<'EOF'
auth required pam_u2f.so cue userverification=1 authfile=/etc/u2f_keys
EOF

pamtester u2ftest "$USER" authenticate
```
Kỳ vọng: được nhắc chạm → **quét vân tay** → `pamtester: successfully authenticated`.

> Nếu chưa đạt, xem mục **Xử lý sự cố** ở cuối. **Đừng** sang bước 5 khi bước này chưa xanh.

---

## 5. Bật cho Đăng nhập + Khoá màn hình

```bash
# 5.1 Lưới cứu hộ: mở TTY (Ctrl+Alt+F3), đăng nhập bằng mật khẩu, chạy 'sudo -i' và GIỮ NGUYÊN.
#     Quay lại giao diện đồ hoạ bằng Ctrl+Alt+F2 (hoặc F1).

# 5.2 Sao lưu file gốc:
sudo cp /etc/pam.d/gdm-password /root/gdm-password.bak

# 5.3 Sửa file:
sudo nano /etc/pam.d/gdm-password
```
Thêm **đúng một dòng** ngay **phía trên** dòng `@include common-auth`:
```
auth    sufficient      pam_u2f.so cue userverification=1 authfile=/etc/u2f_keys
```
Phần đầu file sẽ thành:
```
auth    requisite       pam_nologin.so
auth    required        pam_succeed_if.so user != root quiet_success
auth    sufficient      pam_u2f.so cue userverification=1 authfile=/etc/u2f_keys
@include common-auth
```

**Ý nghĩa:** có khoá + vân tay đúng → vào thẳng (**passwordless**); không có khoá / vân tay sai → tự rơi về
ô **mật khẩu** (dự phòng, không khoá máy).

---

## 6. Kiểm thử đúng thứ tự (quan trọng)

1. **Test khoá màn hình trước** (ít rủi ro hơn): nhấn `Super+L` để khoá → đánh thức → phải được nhắc chạm,
   **quét vân tay** để mở, không cần mật khẩu.
2. Ổn rồi mới **Đăng xuất / đăng nhập lại** để test màn hình đăng nhập.
3. Nếu hỏng: quay về TTY cứu hộ (5.1) và phục hồi:
   ```bash
   sudo cp /root/gdm-password.bak /etc/pam.d/gdm-password
   ```

> **Ghi chú GNOME Keyring:** khi đăng nhập passwordless, "chùm chìa khoá" GNOME (lưu mật khẩu Wi-Fi…) có thể
> không tự mở và hỏi mật khẩu riêng lần đầu — đây là hành vi bình thường, không phải lỗi.

---

## 7. Thu hồi / gỡ khoá khi bị mất

Vì mật khẩu vẫn là phương án dự phòng, **mất khoá không bị khoá máy** — đăng nhập bằng mật khẩu rồi dọn:

**A. Thu hồi một khoá cụ thể (còn giữ khoá khác):**
```bash
sudo nano /etc/u2f_keys
# Xoá phần credential của khoá bị mất khỏi dòng user (đoạn giữa các dấu ":"). Lưu lại.
```
Khoá đó lập tức không còn được chấp nhận.

**B. Tắt hẳn FIDO2, quay về chỉ mật khẩu:**
```bash
sudo sed -i '/pam_u2f.so/ s/^/#/' /etc/pam.d/gdm-password   # comment dòng u2f
# hoặc xoá file ánh xạ:
sudo rm -f /etc/u2f_keys
```

**C. Xoá sạch trên chính thiết bị (nếu tìm lại được, hoặc muốn tái sử dụng):**
```bash
fido2-token -L                 # tìm /dev/hidrawX
fido2-token -R /dev/hidraw4    # RESET: xoá toàn bộ credential + PIN + vân tay trên thiết bị
```

---

## 8. Khôi phục khẩn cấp (nếu lỡ bị khoá ngoài)

1. `Ctrl+Alt+F3` → đăng nhập TTY bằng **mật khẩu** (service `login` không bị sửa) →
   `sudo cp /root/gdm-password.bak /etc/pam.d/gdm-password`.
2. Không vào được TTY → khởi động vào **Recovery mode** (giữ `Shift`/`Esc` lúc boot → GRUB →
   *Advanced options* → *(recovery mode)* → *root shell*) → `mount -o remount,rw /` → phục hồi file backup.

---

## 9. Xử lý sự cố

| Hiện tượng | Nguyên nhân / cách xử lý |
|---|---|
| `fido2-token -L` không thấy thiết bị | Cắm lại; kiểm tra quyền `/dev/hidraw*` (ACL `uaccess`). Đăng nhập lại phiên. |
| pamtester `Authentication failure` | Thêm `debug` vào dòng `pam_u2f.so` trong `/etc/pam.d/u2ftest` rồi chạy lại để xem log chi tiết. |
| Chạm mà không nhận | Đảm bảo dùng **đúng ngón đã enroll**; sai >5 lần trong một lần cắm sẽ **khoá UV tạm** → rút/cắm lại thiết bị để reset. |
| Enroll vân tay báo "operation cancelled" | Thường do template cũ còn trong cảm biến sau khi nạp lại applet — firmware/applet đã tự xoá slot trước khi enroll; thử lại. |
| **Firefox** (bản Snap) không nhận khoá (nhưng Chrome được) | Snap chặn thiết bị custom. Thêm udev rule: xem mục dưới. |

### Firefox (Snap) không truy cập được thiết bị
Firefox bản Snap chỉ cho phép danh sách VID/PID cố định. Thêm thiết bị BMC vào:
```bash
sudo tee /etc/udev/rules.d/71-bmc-fido.rules >/dev/null <<'EOF'
SUBSYSTEM=="hidraw", KERNEL=="hidraw*", ATTRS{idVendor}=="1fc9", ATTRS{idProduct}=="0117", TAG+="snap_firefox_firefox", TAG+="uaccess"
EOF
sudo udevadm control --reload-rules && sudo udevadm trigger
```
Rồi rút/cắm lại thiết bị và khởi động lại Firefox. (Hoặc dùng Firefox bản `.deb` không-snap.)

---

## 10. Ghi chú bảo mật

- **`userverification=1`** yêu cầu **vân tay** (đặt cờ UV chuẩn CTAP2.1). Trên thiết bị này, kể cả
  `userverification=0` cũng vẫn bắt vân tay khớp, nhưng nên dùng `=1` cho đúng chuẩn.
- Dùng `required` (2FA: mật khẩu + khoá) hay `sufficient` (passwordless: chỉ khoá) tuỳ nhu cầu.
  `sufficient` tiện nhưng rủi ro khoá cao hơn nếu mất khoá — **luôn giữ mật khẩu fallback**.
- File `/etc/u2f_keys` chỉ chứa **khoá công khai + credential ID** (không phải bí mật), nhưng phải để
  **root sở hữu** (không cho user thường ghi) để tránh leo thang đặc quyền.
- Đăng nhập vật lý qua vân tay yêu cầu **có mặt thiết bị**; luôn có sẵn phương án dự phòng (mật khẩu, khoá thứ 2).
