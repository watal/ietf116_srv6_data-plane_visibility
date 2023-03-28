# IETF116 SRv6 Data-Plane Visibility

* [Hackathonページ](https://wiki.ietf.org/en/meeting/116/hackathon)

* Draft
    * [Export of Segment Routing over IPv6 Information in IP Flow Information Export (IPFIX)](https://datatracker.ietf.org/doc/draft-ietf-opsawg-ipfix-srv6-srh/) 
        * IPFIXにSRの情報を乗せるためにIE (IPFIX Information Elements) を追加
    * [Export of On-Path Delay in IPFIX](https://datatracker.ietf.org/doc/html/draft-ietf-opsawg-ipfix-on-path-telemetry)
        * IPFIXに遅延情報を載せて、On-path Telemetryで計測

## prepare

```shell
sudo apt install clang llvm libelf-dev build-essential gcc-multilib linux-libc-dev libbpf-dev
```

```shell
go generate ./...

make test
```
