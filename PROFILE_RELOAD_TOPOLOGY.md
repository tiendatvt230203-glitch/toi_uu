# TOPO NẠP VÀ RELOAD MỘT PROFILE

Tài liệu này giữ đúng khung topo gốc: `app_config` → `ne_pair` →
`handle_profile_notify()` → `apply_active_configs()` → `runtime_start()` →
`forwarder_run()`. Các mục bên dưới chỉ sửa những nút đã bị gỡ hoặc đổi tên
trong source hiện tại; không tự lược bỏ nhánh của topo gốc.

## 0. Những gì đã gỡ khỏi topo gốc

```text
TOPO GỐC
│
├── config_db_unchanged()                 [ĐÃ GỠ]
├── profile_db_unchanged()                [ĐÃ GỠ]
├── lan_wan_db_unchanged()                [ĐÃ GỠ]
├── active_profile_unchanged()            [ĐÃ GỠ]
└── runtime_tuning_only_change()          [ĐÃ GỠ]
```

Các hàm trên từng chia cùng một việc so sánh profile ra nhiều tầng và có phần
trùng nhau. Source hiện tại thay toàn bộ cụm đó bằng đúng một cửa kiểm tra:

```text
active_profile_config_unchanged(CONFIG CŨ, CONFIG MỚI)
│
├── profile_name + enabled
├── interfaces_unchanged()
│   ├── locals[]
│   └── wans[] + bandwidth_weight
├── bridges_unchanged()
├── policies_db_unchanged()
└── pqc_unchanged()
```

Những trường từng xuất hiện trong nhánh “so thông tin tổng” nhưng nay không
được so độc lập:

```text
profile_id
    └── chuyển lên handle_profile_notify():
        khác ID → return_to_blank_daemon() → nạp profile mới

crypto_enabled
    └── dẫn xuất từ policies[] nên kiểm tra qua policies[]

fake_ethertype_ipv4
    └── giá trị dẫn xuất, không phải dữ liệu edit độc lập

bpf_lan_file / bpf_wan_file
    └── đường dẫn cố định, UI không chỉnh sửa
```

Phạm vi tài liệu dừng đúng tại `forwarder_run()`, không mở tiếp các nhánh xử
lý packet bên trong dataplane.

## 1. Cấu trúc `app_config`

```text
                              app_config
                                  │
          ┌───────────────────────┼────────────────────────┐
          │                       │                        │
          ▼                       ▼                        ▼
    Thông tin profile         Interfaces                Policies
          │                       │                        │
          ├── profile_id          ├── locals[]             ├── policies[]
          ├── profile_name        │     └── ifname          │     ├── db_id
          └── enabled             │                        │     ├── priority
                                  └── wans[]               │     ├── action
                                        ├── ifname         │     ├── protocol
                                        ├── dst_ip         │     ├── source match
                                        ├── dataplane      │     └── destination match
                                        └── bandwidth_weight

          ┌───────────────────────┼────────────────────────┐
          │                       │                        │
          ▼                       ▼                        ▼
       bridges[]                  pqc              Giá trị dẫn xuất/cố định
          │                       │                        │
          ├── local_slot          ├── local_identity_      ├── crypto_enabled
          ├── wan_slot            │   fingerprint          ├── fake_ethertype_ipv4
          └── ifname              ├── peer_fingerprint     ├── bpf_lan_file
                                  ├── is_initiator         └── bpf_wan_file
                                  ├── has_pqc_identity
                                  └── peer_public_key
```

Ý nghĩa quan trọng:

```text
profile_id
    └── xác định profile duy nhất mà daemon đang chạy

locals[] + wans[] + bridges[]
    └── xác định topology interface của profile

policies[]
    └── xác định traffic nào BYPASS hoặc ENCRYPT

crypto_enabled
    └── giá trị được suy ra từ policies[]:
        có ít nhất một policy mã hóa thì crypto_enabled = 1

fake_ethertype_ipv4
    └── giá trị phục vụ dataplane mã hóa, không phải trường edit độc lập

bpf_lan_file + bpf_wan_file
    └── đường dẫn cố định của chương trình, không phải trường do UI thay đổi
```

Vì vậy khi kiểm tra một profile đang được edit, code so sánh nguồn sự thật là
`policies[]`, không so riêng `crypto_enabled`. Tương tự, không cần xem
`fake_ethertype_ipv4` hoặc đường dẫn BPF là một thay đổi profile độc lập.

## 2. Cấu trúc runtime

```text
                          runtime_state
                                │
            ┌───────────────────┼───────────────────┐
            │                   │                   │
            ▼                   ▼                   ▼
       Thread state          forwarder          Config slots
            │                   │                   │
            ├── thread          └── fwd              ├── cfg_slots[0]
            ├── has_thread                          ├── cfg_slots[1]
            └── running                             └── active_slot
```

Hai phần tử `cfg_slots[2]` không phải hai profile chạy đồng thời. Chúng là hai
phiên bản cũ/mới của cùng profile đang active:

```text
cfg_slots[active_slot]
    └── CONFIG CŨ mà dataplane đang sử dụng

cfg_slots[1 - active_slot]
    └── CONFIG MỚI vừa đọc từ PostgreSQL
```

Khi đổi sang một `profile_id` khác, code không dùng hai slot để trộn hai
profile. Runtime cũ bị xóa hoàn toàn trước, rồi profile mới được nạp như lần
khởi động đầu tiên từ daemon rỗng.

## 3. Cấu trúc `ne_pair`

```text
                                  ne_pair
                                     │
        ┌────────────────────────────┼────────────────────────────┐
        │                            │                            │
        ▼                            ▼                            ▼
       UMEM                       Interfaces                   Frame pool
        │                            │                            │
        ├── bufs              ┌──────┴──────┐                     └── pool
        ├── bufsize           │             │                           │
        ├── frame_size        ▼             ▼                           ├── buf[]
        ├── n_frames       locals[]       wans[]                        ├── cap
        ├── umem              │             │                           ├── head
        ├── umem_fq_li        ▼             ▼                           ├── tail
        └── umem_fq_q      ne_iface      ne_iface                       └── lock
                               │             │
                               └──────┬──────┘
                                      ▼
                                  queues[]
                                      │
                                      ▼
                                ne_xsk_queue

ne_pair
│
├── LAN state
│   ├── locals[MAX_INTERFACES]
│   ├── local_count
│   ├── local_queue_total
│   └── local_live[]
│
├── WAN state
│   ├── wans[MAX_INTERFACES]
│   ├── wan_count
│   ├── wan_queue_total
│   └── wan_live[]
│
├── BPF/XDP state
│   ├── bpf_locals[]
│   ├── bpf_wans[]
│   ├── xdp_local_on[]
│   ├── xdp_wan_on[]
│   └── xdp_flags
│
└── UMEM/frame ownership
    ├── umem
    ├── pool
    ├── umem_fq_li
    └── umem_fq_q
```

## 4. Từ lệnh `-id` tới daemon

```text
Terminal phụ
│
└── ./network-encryptor -id <ID>
    │
    ├── parse_startup_profile_id()
    ├── load_ne_env()
    ├── notify_profile_load(ID)
    │   └── PostgreSQL: pg_notify("xdp_start", "load:<ID>")
    └── process gửi lệnh kết thúc


Daemon chính
│
├── LISTEN xdp_start
├── select()
├── PQconsumeInput()
├── PQnotifies()
├── parse_notify_profile_cmd("load:<ID>")
└── handle_profile_notify(rt, &active_profile_id, ID)
```

## 5. Chi tiết `handle_profile_notify()`

```text
handle_profile_notify(rt, active_profile_id, profile_id)
│
├── [1] g_stop_requested ?
│   │
│   ├── YES ──► return 0
│   └── NO  ──► tiếp tục
│
├── [2] ne_profile_id_exists(profile_id)
│   │
│   ├── PROFILE KHÔNG TỒN TẠI
│   │   │
│   │   ├── log: profile not found
│   │   ├── return_to_blank_daemon()
│   │   └── return 0
│   │
│   └── PROFILE TỒN TẠI
│       └── tiếp tục
│
├── [3] Kiểm tra runtime hiện tại
│   │
│   ├── Case A: has_thread == 1 nhưng active_profile_id <= 0
│   │   └── stale dataplane
│   │       └── return_to_blank_daemon()
│   │
│   ├── Case B: has_thread == 1 nhưng running == 0
│   │   └── dataplane thread đã chết/không chạy
│   │       └── return_to_blank_daemon()
│   │
│   ├── Case C: active_profile_id > 0
│   │           và active_profile_id != profile_id
│   │   │
│   │   │   Ví dụ: đang chạy ID 3, nhận notify ID 5
│   │   │
│   │   ├── log: replace profile 3 → 5
│   │   ├── return_to_blank_daemon()
│   │   │   └── xóa sạch runtime của profile 3
│   │   └── đi tiếp xuống bước [4]
│   │       └── profile 5 được nạp như profile mới từ daemon rỗng
│   │
│   └── Case D: active_profile_id == profile_id
│       └── đây là lệnh edit/reload chính profile đang chạy
│
└── [4] load_profile_and_run(rt, active_profile_id, profile_id)
    │
    ├── apply_active_configs(rt, profile_id)
    └── thành công:
        └── *active_profile_id = profile_id
```

Điểm phân nhánh chính:

```text
                      ID nhận được
                           │
              ┌────────────┴────────────┐
              │                         │
       khác active ID             trùng active ID
              │                         │
              ▼                         ▼
 return_to_blank_daemon()       kiểm tra nội dung edit
              │                         │
              ▼                         ├── không đổi: giữ nguyên
 nạp mới từ daemon rỗng                  ├── đổi topology: restart
                                        └── cùng topology: hot reload
```

## 6. Chi tiết `return_to_blank_daemon()`

```text
return_to_blank_daemon(rt, active_profile_id)
│
├── *active_profile_id = 0
│
├── rt->has_thread ?
│   └── YES: runtime_stop_forwarder(rt)
│       │
│       ├── forwarder_stop()
│       ├── forwarder_shutdown_resources()
│       ├── pthread_join(rt->thread)
│       │   └── chờ forwarder_thread_main() kết thúc hoàn toàn
│       ├── forwarder_cleanup(&rt->fwd)
│       ├── interface_promisc_off_config(active cfg)
│       ├── rt->has_thread = 0
│       └── rt->running = 0
│
├── sig_pqc_prepare_reload()
├── sig_pqc_finalize_reload()
├── forwarder_clear_stop()
├── main_diag_ne_pqc_clear_all()
├── memset(rt, 0, sizeof(*rt))
└── daemon_idle_log()
    └── daemon trở lại trạng thái chờ lệnh `-id`
```

Hàm này không nạp profile. Nó chỉ đưa chương trình về trạng thái daemon rỗng.
Sau khi đổi ID, `handle_profile_notify()` tiếp tục gọi
`load_profile_and_run()` để nạp ID mới.

## 7. Chi tiết `apply_active_configs()`

```text
apply_active_configs(rt, profile_id)
│
├── [7.1] calloc(1, sizeof(app_config))
│   └── tạo new_cfg tạm
│
├── [7.2] load_active_profile_config(new_cfg, profile_id)
│   │
│   └── đọc PostgreSQL và dựng toàn bộ app_config
│       ├── profile_id / profile_name / enabled
│       ├── locals[]
│       ├── wans[] / bandwidth_weight
│       ├── bridges[]
│       ├── policies[]
│       ├── pqc
│       └── các giá trị runtime dẫn xuất/cố định
│
└── rt->has_thread == 0 ?
    │
    ├── YES: DATAPLANE CHƯA CHẠY
    │   │
    │   ├── main_diag_log_db_apply(new_cfg)
    │   ├── runtime_start(rt, new_cfg)
    │   ├── copy config vào cfg_slots[0]
    │   └── free(new_cfg)
    │
    └── NO: DATAPLANE ĐANG CHẠY, CÙNG PROFILE ID
        │
        ├── next_slot = 1 - active_slot
        ├── prev_cfg = &cfg_slots[active_slot]
        │   └── CONFIG CŨ đang chạy
        ├── cfg_slots[next_slot] = *new_cfg
        │   └── CONFIG MỚI vừa đọc từ DB
        ├── free(new_cfg)
        └── chuyển sang kiểm tra edit
```

Trạng thái hai slot lúc này:

```text
┌────────────────────────────────────────────────────┐
│                    runtime_state                   │
│                                                    │
│ cfg_slots[active_slot] = CONFIG CŨ đang chạy       │
│ cfg_slots[next_slot]   = CONFIG MỚI vừa đọc từ DB  │
│                                                    │
│ prev_cfg ─────────────► CONFIG CŨ                  │
└────────────────────────────────────────────────────┘
```

## 8. Kiểm tra profile cùng ID có thay đổi không

```text
active_profile_config_unchanged(CONFIG CŨ, CONFIG MỚI)
│
├── [1] Thông tin profile có thể edit
│   ├── enabled
│   └── profile_name
│
├── [2] interfaces_unchanged()
│   │
│   ├── local_count
│   ├── từng LAN được tìm theo ifname
│   ├── wan_count
│   └── từng WAN được tìm theo ifname rồi so:
│       ├── ifname
│       ├── dst_ip
│       ├── dataplane
│       └── bandwidth_weight
│
├── [3] bridges_unchanged()
│   ├── bridge_count
│   └── từng bridge:
│       ├── local_slot
│       ├── wan_slot
│       └── ifname
│
├── [4] policies_db_unchanged()
│   ├── policy_count
│   ├── tìm policy mới bằng db_id
│   └── policy_fields_equal()
│       ├── id / db_id / priority
│       ├── action / protocol
│       ├── source/destination port range
│       ├── source/destination network + mask
│       ├── any flags
│       └── negate flags
│
└── [5] pqc_unchanged()
    ├── local_identity_fingerprint
    ├── peer_fingerprint
    ├── is_initiator
    ├── has_pqc_identity
    └── peer_public_key
```

Các trường cố ý không so độc lập:

```text
profile_id
    └── đã được xử lý trước tại handle_profile_notify():
        khác ID thì clear runtime và nạp mới hoàn toàn

crypto_enabled
    └── được suy ra từ policies[]; policy đã được so đầy đủ

fake_ethertype_ipv4
    └── giá trị dẫn xuất, không phải input edit độc lập

bpf_lan_file / bpf_wan_file
    └── đường dẫn cố định của chương trình
```

## 9. Đọc lại DB sau 500 ms

```text
Lần so sánh thứ nhất: OLD == NEW ?
│
├── NO
│   └── đã thấy thay đổi → phân loại reload ngay
│
└── YES
    │
    ├── có thể NOTIFY tới trước khi transaction PostgreSQL commit hoàn tất
    ├── chờ 500 ms
    ├── load_active_profile_config() lần thứ hai
    └── active_profile_config_unchanged() lần thứ hai
        │
        ├── vẫn SAME
        │   ├── log policy db_ids
        │   ├── main_diag_log_no_update()
        │   └── return 0, giữ nguyên dataplane
        │
        └── DIFFERENT
            └── CONFIG CHANGED → phân loại reload
```

## 10. Phân loại thay đổi

```text
CONFIG CHANGED
│
├── forwarder_same_topology(CONFIG CŨ, CONFIG MỚI)
│   │
│   ├── so local_count và wan_count
│   ├── kiểm tra toàn bộ LAN ifname cũ còn trong config mới
│   └── kiểm tra toàn bộ WAN ifname cũ còn trong config mới
│
└── topology giống nhau?
    │
    ├── NO: có thêm/bớt/đổi interface
    │   └── FULL DATAPLANE RESTART
    │
    └── YES: tập LAN/WAN giữ nguyên
        └── HOT RELOAD
```

Lưu ý: `forwarder_same_topology()` chỉ quyết định có thể giữ nguyên hạ tầng
interface/XSK hay không. Các thay đổi policy, PQC, bridge, WAN setting hoặc
weight vẫn được phát hiện ở bước so config và được áp dụng bằng hot reload.

## 11. Nhánh full restart khi topology đổi

```text
topology khác nhau
│
├── main_diag_log_db_apply(CONFIG MỚI, CONFIG CŨ)
├── runtime_stop_forwarder(rt)
│   ├── forwarder_stop()
│   ├── forwarder_shutdown_resources()
│   ├── pthread_join()
│   ├── forwarder_cleanup()
│   └── promisc off
│
├── g_stop_requested ?
│   └── YES → hủy reload
│
├── active_slot = next_slot
├── runtime_start(rt, cfg_slots[active_slot])
└── dataplane được dựng mới bằng CONFIG MỚI
```

Đây vẫn là restart nội bộ dataplane; process daemon và kết nối LISTEN vẫn tồn
tại, không cần khởi động lại executable.

## 12. Nhánh hot reload khi topology giữ nguyên

```text
topology giống nhau
│
├── forwarder_reload_config(&rt->fwd, CONFIG MỚI)
│   │
│   ├── xác nhận lại forwarder_same_topology()
│   ├── wait_dataplane_workers()
│   ├── forwarder_queue_reload()
│   │   ├── đặt reload_fwd / reload_cfg
│   │   ├── reload_pending = 1
│   │   └── thread gọi notify chờ mid core áp dụng
│   │
│   └── mid core gọi fwd_reload_apply_if_pending()
│       └── forwarder_reload_config_impl()
│           ├── fwd_wan_configure_live_drains()
│           ├── profile_iface_xdp_sync_wan_live()
│           ├── fwd->cfg = CONFIG MỚI
│           ├── fwd_wan_weight_blend_begin()
│           ├── nếu crypto_enabled:
│           │   └── pqc_handshake_start_all_profiles()
│           ├── fwd_crypto_snapshot_active_to_prev()
│           ├── fwd_crypto_rebuild()
│           ├── wan_failover_on_cfg()
│           └── mac_learn_restore()
│
├── HOT RELOAD THÀNH CÔNG
│   ├── active_slot = next_slot
│   └── CONFIG MỚI trở thành config đang chạy
│
└── HOT RELOAD THẤT BẠI
    ├── không đổi active_slot
    └── dataplane tiếp tục giữ CONFIG CŨ
```

## 13. `runtime_start()` đến `forwarder_run()`

```text
runtime_start(rt, cfg)
│
├── active_slot = 0
├── cfg_slots[0] = *cfg
├── running = 0
├── forwarder_clear_stop()
└── pthread_create(&rt->thread, ..., forwarder_thread_main, rt)
    │
    ├── thành công
    │   └── has_thread = 1
    │
    └── thread mới chạy forwarder_thread_main(rt)
        │
        ├── forwarder_pin_cpu()
        ├── forwarder_init(&rt->fwd, &cfg_slots[active_slot])
        │   │
        │   ├── thất bại
        │   │   ├── forwarder_cleanup()
        │   │   ├── running = 0
        │   │   └── thread kết thúc
        │   │
        │   └── thành công
        │       └── dataplane đã được dựng
        │
        ├── forwarder_should_stop() ?
        │   └── YES
        │       ├── forwarder_cleanup()
        │       ├── running = 0
        │       └── thread kết thúc
        │
        ├── running = 1
        ├── forwarder_run(&rt->fwd)
        │   └── bắt đầu vòng chạy dataplane
        └── khi forwarder_run() thoát:
            └── running = 0
```

Điểm dừng của topo tài liệu này là `forwarder_run()`. Các nhánh xử lý LAN RX,
WAN RX, crypto, TX, bonding TCP/UDP và failover nằm sau điểm này và không được
mở rộng trong sơ đồ hiện tại.

## 14. Toàn bộ luồng rút gọn để đối chiếu

```text
./network-encryptor -id <ID>
│
└── PostgreSQL NOTIFY load:<ID>
    │
    └── daemon: handle_profile_notify(ID)
        │
        ├── ID không tồn tại
        │   └── return_to_blank_daemon()
        │
        ├── ID khác profile đang chạy
        │   ├── return_to_blank_daemon()
        │   └── load_profile_and_run(ID mới)
        │       └── runtime_start()
        │           └── forwarder_init()
        │               └── forwarder_run()
        │
        └── ID trùng profile đang chạy
            └── apply_active_configs()
                │
                ├── nội dung không đổi
                │   └── giữ nguyên dataplane
                │
                ├── LAN/WAN topology đổi
                │   ├── runtime_stop_forwarder()
                │   └── runtime_start(CONFIG MỚI)
                │       └── forwarder_init()
                │           └── forwarder_run()
                │
                └── topology giữ nguyên, nội dung có đổi
                    └── forwarder_reload_config(CONFIG MỚI)
                        ├── thành công: đổi active_slot
                        └── thất bại: giữ CONFIG CŨ
```
