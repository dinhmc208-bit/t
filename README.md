# nVNC - VNC Scanner & Brute Force Tool (Rust)

Phiên bản Rust của công cụ VNC Scanner với khả năng xử lý tối đa 20,000 concurrent connections.

## Tính năng

- **Scanning**: Quét IP ranges để tìm VNC servers
- **Brute Force**: Thử các mật khẩu trên các VNC servers đã tìm thấy
- **High Performance**: Hỗ trợ tối đa 20,000 concurrent connections sử dụng async/await
- **CLI Interface**: Giao diện dòng lệnh tương tác
- **Configuration**: Quản lý cấu hình linh hoạt

## Yêu cầu

- Rust 1.70+ với Cargo
- Windows/Linux/macOS

## Cài đặt

```bash
cargo build --release
```

## Sử dụng

### Chạy chương trình

```bash
cargo run --release
```

### Các lệnh

- `scan <range>` - Quét IP range (ví dụ: `scan 192.168.*.*`)
- `brute` - Bắt đầu brute force trên các IP đã scan
- `set <key> <value>` - Thiết lập cấu hình
- `show <type>` - Hiển thị kết quả (ips, results, passwords, settings)
- `add <value> <file>` - Thêm giá trị vào file (ips, passwords, results)
- `flush <file>` - Xóa nội dung file
- `clear` / `cls` - Xóa màn hình
- `disclaimer` - Hiển thị disclaimer
- `exit` / `quit` / `q` - Thoát

### Cấu hình

Các tham số có thể cấu hình:

- `scan_range` - IP range để scan (ví dụ: `192.168.*.*`)
- `scan_port` - Port để scan (mặc định: 5900)
- `scan_timeout` - Timeout cho scan (giây)
- `scan_threads` - Số lượng concurrent connections cho scan (tối đa 20000)
- `brute_threads` - Số lượng concurrent connections cho brute force (tối đa 20000)
- `brute_timeout` - Timeout cho brute force (giây)
- `auto_save` - Tự động lưu config (true/false)
- `auto_brute` - Tự động chạy brute force sau khi scan (true/false)

### Ví dụ

```bash
# Thiết lập scan range
+> set scan_range 192.168.1.*

# Thiết lập số threads
+> set scan_threads 10000

# Bắt đầu scan
+> scan 192.168.1.*

# Xem kết quả scan
+> show ips

# Bắt đầu brute force
+> brute

# Xem kết quả brute force
+> show results
```

## Cấu trúc thư mục

```
nvnc/
├── src/
│   ├── main.rs          # Entry point
│   ├── config.rs        # Configuration management
│   ├── des.rs           # DES encryption
│   ├── rfb.rs           # RFB/VNC protocol
│   ├── net_tools.rs     # IP utilities
│   ├── files.rs         # File handling
│   ├── scan_engine.rs   # Scanning engine
│   ├── brute_engine.rs  # Brute force engine
│   ├── display.rs       # Display utilities
│   └── cli.rs           # CLI interface
├── output/              # Kết quả scan và brute force
│   ├── ips.txt
│   └── results.txt
├── input/               # Input files
│   └── passwords.txt
└── bin/                 # Config files
    └── config.conf
```

## Lưu ý

⚠️ **DISCLAIMER**: Đây là công cụ đánh giá bảo mật. Chỉ sử dụng trên các hệ thống mà bạn có quyền kiểm tra. Không khuyến khích các hoạt động bất hợp pháp.

## So sánh với phiên bản Python

- **Performance**: Nhanh hơn đáng kể nhờ Rust và async/await
- **Memory**: Sử dụng bộ nhớ hiệu quả hơn
- **Concurrency**: Hỗ trợ tối đa 20k concurrent connections
- **Type Safety**: An toàn kiểu dữ liệu tốt hơn với Rust

## License

Sử dụng cho mục đích giáo dục và đánh giá bảo mật hợp pháp.

