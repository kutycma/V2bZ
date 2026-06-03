# V2bZ

Backend node V2board dựa trên nhiều core, được phát triển từ XrayR.

**Lưu ý:** dự án này cần dùng cùng bản V2board đã chỉnh sửa: https://github.com/wyx2685/v2board

## Tính năng

* Mã nguồn mở và miễn phí.
* Hỗ trợ Vmess/Vless, Trojan, Shadowsocks, Hysteria1/2 và nhiều giao thức khác.
* Hỗ trợ Vless, XTLS và các tính năng mới liên quan.
* Một instance có thể kết nối nhiều node, không cần chạy nhiều tiến trình lặp lại.
* Hỗ trợ giới hạn IP online.
* Hỗ trợ giới hạn số kết nối TCP.
* Hỗ trợ giới hạn tốc độ theo cổng node và theo user.
* Cấu hình rõ ràng, dễ chỉnh.
* Tự khởi động lại instance khi cấu hình thay đổi.
* Hỗ trợ nhiều core, dễ mở rộng.
* Hỗ trợ build theo tag để chỉ biên dịch core cần dùng.

## Ma trận tính năng

| Tính năng | v2ray | trojan | shadowsocks | hysteria1/2 |
|---|---|---|---|---|
| Tự xin chứng chỉ TLS | Có | Có | Có | Có |
| Tự gia hạn chứng chỉ TLS | Có | Có | Có | Có |
| Thống kê user online | Có | Có | Có | Có |
| Rule audit | Có | Có | Có | Có |
| DNS tuỳ chỉnh | Có | Có | Có | Có |
| Giới hạn số IP online | Có | Có | Có | Có |
| Giới hạn số kết nối | Có | Có | Có | Có |
| Giới hạn IP xuyên node | Có | Có | Có | Có |
| Giới hạn tốc độ theo user | Có | Có | Có | Có |
| Giới hạn tốc độ động (chưa kiểm thử) | Có | Có | Có | Có |

## TODO

- [ ] Làm lại giới hạn tốc độ động
- [ ] Hoàn thiện tài liệu sử dụng

## Cài đặt

### Cài đặt một lệnh

```bash
wget -N https://raw.githubusercontent.com/kutycma/V2bZ-script/master/install.sh && bash install.sh
```

### Cài đặt thủ công

[Hướng dẫn cài đặt thủ công](https://v2bz.v-50.me/v2bz/v2bz-xia-zai-he-an-zhuang/install/manual)

## Build

```bash
# Dùng -tags để chọn core cần biên dịch: xray, sing, hysteria2
GOEXPERIMENT=jsonv2 go build -v -o build_assets/V2bZ -tags "sing xray hysteria2 with_quic with_grpc with_utls with_wireguard with_acme with_gvisor" -trimpath -ldflags "-X 'github.com/kutycma/V2bZ/cmd.version=$version' -s -w -buildid="
```

## Cấu hình và tài liệu

[Tài liệu sử dụng chi tiết](https://v2bz.v-50.me/)

## Miễn trừ trách nhiệm

* Dự án phục vụ nhu cầu cá nhân nên không cam kết tương thích ngược.
* Không cam kết mọi tính năng đều hoạt động trong mọi môi trường; nếu gặp lỗi hãy mở issue.
* Người dùng tự chịu trách nhiệm với mọi hậu quả phát sinh từ việc sử dụng dự án.
* Cấu trúc dự án có thể thay đổi theo nhu cầu phát triển.

## Cảm ơn

* [Project X](https://github.com/XTLS/)
* [V2Fly](https://github.com/v2fly)
* [VNet-V2ray](https://github.com/ProxyPanel/VNet-V2ray)
* [Air-Universe](https://github.com/crossfw/Air-Universe)
* [XrayR](https://github.com/XrayR/XrayR)
* [sing-box](https://github.com/SagerNet/sing-box)

## Lịch sử sao

[![Stargazers over time](https://starchart.cc/kutycma/V2bZ.svg)](https://starchart.cc/kutycma/V2bZ)
