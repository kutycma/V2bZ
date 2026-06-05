# V2bZ

Backend node cho ZicBoard/V2Board theo hướng UniProxy legacy, phát triển từ nền XrayR/V2bX và hỗ trợ nhiều core.

## Lưu Ý Quan Trọng Cho ZicBoard

V2bZ dùng API UniProxy legacy:

```text
/api/v3/server/UniProxy/config
/api/v3/server/UniProxy/user
/api/v3/server/UniProxy/push
/api/v3/server/UniProxy/alive
```

Vì vậy trong ZicBoard hãy tạo node legacy riêng như `VMess`, `VLess`, `Trojan`, `Shadowsocks`. Không chọn `ZicNode` hoặc `V2Node` khi dùng V2bZ; hai loại node gom đó thuộc backend ZicNode riêng.

## Matrix Hỗ Trợ

| Core | NodeType hỗ trợ |
|---|---|
| `xray` | `shadowsocks`, `vmess`, `vless`, `trojan` |
| `sing` | `shadowsocks`, `vmess`, `vless`, `trojan`, `hysteria`, `hysteria2`, `tuic`, `anytls` |
| `hysteria2` | `hysteria2` |

Network khuyến nghị khi dùng `xray`:

| Protocol | Network hỗ trợ |
|---|---|
| `vmess`, `vless` | `tcp`, `ws`, `grpc`, `httpupgrade`, `xhttp` |
| `trojan` | `tcp`, `ws`, `grpc` |

Nếu cấu hình nhầm `NodeType=zicnode` hoặc `v2node`, V2bZ sẽ báo lỗi và yêu cầu chọn node legacy qua UniProxy.

## Cài Đặt Một Lệnh

Wizard tiếng Việt:

```bash
wget -N https://raw.githubusercontent.com/kutycma/V2bZ-script/master/install.sh && bash install.sh
```

Cài nhanh:

```bash
bash <(curl -Ls https://raw.githubusercontent.com/kutycma/V2bZ-script/master/install.sh) \
  --quick \
  --api-host https://panel.example.com \
  --api-key SERVER_TOKEN \
  --node-id 1 \
  --node-type vless \
  --core xray
```

Xem config trước khi cài:

```bash
bash install.sh --quick --dry-run \
  --api-host https://panel.example.com \
  --api-key SERVER_TOKEN \
  --node-id 1 \
  --node-type vless \
  --core xray
```

## Auto TLS Và Pinned Cert

Khuyến nghị bật Auto TLS ngay trong panel ZicBoard cho các node legacy có TLS: `vmess`, `vless`, `trojan`, `hysteria/hysteria2`, `tuic`, `anytls`. V2bZ ưu tiên đọc `tls_settings`/`tlsSettings` từ panel; nếu panel không gửi cấu hình cert thì mới dùng `CertConfig` local trong file config.

Khi cấp hoặc renew cert thành công, V2bZ report `sha256`, `source` và `not_after` về `/api/v3/server/UniProxy/cert/report`. ZicBoard dùng `auto_cert.sha256` để tự sinh `pinnedPeerCertSha256` cho client. `shadowsocks` không dùng Auto TLS inbound trong phạm vi này.

Local `CertConfig` có thể dùng làm fallback:

```json
"CertConfig": {
  "CertMode": "none",
  "SelfFallback": false,
  "CertDomain": "",
  "CertFile": "/etc/V2bZ/fullchain.cer",
  "KeyFile": "/etc/V2bZ/cert.key",
  "Provider": "",
  "DNSEnv": {}
}
```

## Config Keys Chính

Ví dụ node config tối thiểu:

```json
{
  "Core": "xray",
  "ApiHost": "https://panel.example.com",
  "ApiKey": "SERVER_TOKEN",
  "NodeID": 1,
  "NodeType": "vless",
  "ListenIP": "0.0.0.0",
  "SendIP": "0.0.0.0",
  "DeviceOnlineMinTraffic": 200,
  "ReportMinTraffic": 0,
  "EnableTFO": true,
  "CertConfig": {
    "CertMode": "none",
    "CertFile": "/etc/V2bZ/fullchain.cer",
    "KeyFile": "/etc/V2bZ/cert.key"
  }
}
```

Script mới dùng `ReportMinTraffic`, `EnableTFO`, `EnableSniff`; không dùng các key cũ `MinReportTraffic`, `TCPFastOpen`, `SniffEnabled`.

## Build

Không cần `GOEXPERIMENT=jsonv2`.

```bash
go test ./...

go build \
  -tags "sing xray hysteria2 with_quic with_grpc with_utls with_wireguard with_acme with_gvisor" \
  -o build_assets/V2bZ \
  -trimpath \
  -ldflags "-X 'github.com/kutycma/V2bZ/cmd.version=$version' -s -w -buildid="
```

## Lệnh Quản Lý Sau Khi Cài

```bash
V2bZ            # mở menu
V2bZ status     # xem trạng thái
V2bZ log        # xem log
V2bZ generate   # tạo lại config UniProxy
V2bZ restart    # khởi động lại service
```

## Miễn Trừ Trách Nhiệm

Dự án phục vụ nhu cầu vận hành riêng. Hãy kiểm tra kỹ trên node thử nghiệm trước khi dùng production, đặc biệt với TLS/Reality/network nâng cao.
