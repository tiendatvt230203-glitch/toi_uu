# TOPO KHỞI ĐỘNG VÀ TƯƠNG TÁC PROFILE

## 1. `main()` chỉ điều phối

```text
main()
│
├── handle_cli_command()
│
├── daemon_connect_vault_db()
│
├── daemon_setup_core_once()
│
├── daemon_run_profile_events()
│
└── daemon_cleanup()
```

`main()` không trực tiếp chứa logic PostgreSQL, Vault, PQC, dataplane hoặc xử
lý profile. Mỗi lời gọi tương ứng với một giai đoạn rõ ràng của chương trình.

## 2. Xử lý lệnh CLI

```text
handle_cli_command(argc, argv)
│
├── lệnh PQC IPC
│   └── sig_pqc_handle_ipc_cli()
│
├── -gi
│   └── tạo identity PQC
│
├── -gs <interface|bridge>
│   └── truy vấn trạng thái CFM
│
├── -di/-ai <wan>
│   ├── đọc thông tin DB từ Vault
│   └── gửi PostgreSQL NOTIFY cho daemon
│
├── -id <profile_id>
│   ├── đọc thông tin DB từ Vault
│   └── gửi PostgreSQL NOTIFY "load:<profile_id>"
│
└── không có tham số
    └── chuyển sang chạy daemon
```

Process chạy lệnh `-id`, `-di` hoặc `-ai` chỉ gửi yêu cầu rồi kết thúc. Process
daemon đang chạy mới nhận NOTIFY và thực hiện công việc.

## 3. Kết nối Vault và PostgreSQL

```text
daemon_connect_vault_db()
│
├── load_ne_env()
│   └── mở Vault bằng thông tin bootstrap
│
├── ne_postgres_conn_fill()
│   └── lấy từ Vault:
│       ├── POSTGRES_SERVER
│       ├── POSTGRES_PORT
│       ├── POSTGRES_DB
│       ├── POSTGRES_USER
│       └── POSTGRES_PASSWORD
│
├── in thông tin an toàn
│   └── host / port / dbname / user
│       └── không bao giờ in password
│
├── PQconnectdbParams()
│   └── đăng nhập PostgreSQL
│
└── LISTEN
    ├── xdp_start
    └── xdp_wan_admin
```

Vault chỉ cung cấp bí mật. PostgreSQL chứa profile, LAN/WAN, bridge, policy và
dữ liệu cấu hình cần thiết cho NE/PQC. Vault và DB không sở hữu dataplane.

## 4. Setup core một lần

```text
daemon_setup_core_once()
│
├── trf_pqc_init_global()
├── cài SIGINT/SIGTERM
├── sig_pqc_start_ipc_server()
├── cfm_status_ipc_start()
├── sig_pqc_init_vault()
├── libbpf_set_print()
├── forwarder_pin_cpu()
├── cấp phát runtime của core
└── daemon_idle_log()
```

Đây là phần setup một lần khi daemon khởi động. BE không được điều khiển các
đối tượng thread, forwarder, XDP, UMEM hay tài nguyên core này.

## 5. Vòng tương tác DB

```text
daemon_run_profile_events()
│
├── select() chờ PostgreSQL
│
├── nhận xdp_wan_admin
│   └── handle_wan_admin_notify()
│
├── nhận xdp_start: load:<ID>
│   ├── parse_notify_profile_cmd()
│   └── handle_profile_notify()
│
└── mất kết nối DB
    └── reconnect + LISTEN lại hai channel
```

## 6. Dataplane và ba trường hợp profile

```text
handle_profile_notify(profile_id)
│
├── đọc profile từ DB đúng một lần
│   └── load_active_profile_config()
│
├── DATAPLANE CHƯA TỒN TẠI
│   └── runtime_start()
│       ├── forwarder_init()
│       └── forwarder_run()
│
└── DATAPLANE ĐÃ TỒN TẠI
    │
    ├── IF: ID giống + nội dung UI không đổi
    │   └── giữ nguyên, không làm gì
    │
    ├── ELSE IF: ID giống + nội dung UI thay đổi
    │   └── forwarder_reload_config()
    │       └── giao cấu hình cho dataplane core tự xử lý
    │
    └── ELSE: ID khác
        ├── return_to_blank_daemon()
        │   └── dọn profile/runtime cũ
        └── runtime_start(profile mới)
            └── nạp như lần đầu từ daemon rỗng
```

BE chỉ tạo hoặc chỉnh sửa dữ liệu profile. BE không quyết định core phải
restart, thay XDP, thay UMEM hoặc quản lý thread như thế nào.

## 7. Nội dung được xem là chỉnh sửa từ UI/DB

```text
profile_config_equal(CONFIG CŨ, CONFIG MỚI)
│
├── profile_name / enabled
├── locals[]
├── wans[]
│   ├── ifname
│   ├── dst_ip
│   ├── dataplane
│   └── bandwidth_weight
├── bridges[]
├── policies[]
└── cấu hình PQC của profile
```

Các trường không thuộc quyền chỉnh sửa độc lập của UI và không tham gia phân
loại edit:

```text
fake_ethertype_ipv4
bpf_lan_file
bpf_wan_file
crypto_enabled
```

`crypto_enabled` được suy ra từ `policies[]`; các đường dẫn BPF và EtherType
là cấu hình nội bộ của chương trình.

## 8. Runtime của core

```text
runtime_state
│
├── pthread_t thread
│   └── handle cần cho pthread_join()
│
├── has_thread / running
│   └── trạng thái sẵn sàng của dataplane core
│
├── forwarder fwd
│   └── đối tượng sở hữu trạng thái dataplane
│
└── cfg_slots[2] + active_slot
    └── vùng nhớ config ổn định cho core khi áp dụng edit
```

`runtime_state` không phải dữ liệu của BE. Nó là vùng sở hữu tài nguyên nội bộ
của daemon/core và tồn tại để start, stop, join và cleanup an toàn.

## 9. Thoát chương trình

```text
daemon_cleanup()
│
├── dataplane đang chạy?
│   └── runtime_stop_forwarder()
│
├── free runtime
├── PQfinish()
└── trf_pqc_cleanup()
```
