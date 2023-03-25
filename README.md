# IETF116 SRv6 Data-Plane Visibility

* [Hackathonページ](https://wiki.ietf.org/en/meeting/116/hackathon)
* [事前準備資料](https://docs.google.com/presentation/d/1FClVs3IxOBOvnWAaGJiV__UCkqrUkd7B7H8nkeA_7m4/edit#slide=id.g2238455cc0a_0_16)

* Draft
    * [Export of Segment Routing over IPv6 Information in IP Flow Information Export (IPFIX)](https://wiki.ietf.org/en/meeting/116/hackathon) 
        * IPFIXにSRの情報を乗せるためにIE (IPFIX Information Elements) を追加
    * [Export of On-Path Delay in IPFIX](https://datatracker.ietf.org/doc/html/draft-ietf-opsawg-ipfix-on-path-telemetry)
        * IPFIXに遅延情報を載せて、On-path Telemetryで計測

* 参考になりそうなコード
    * [IPFIX (go)](https://github.com/wide-vsix/linux-flow-exporter)
    * [XDPでIngress/Egress Pachketにタイムスタンプ埋め込んでIn-band Telemetryやるやつ (python)](https://nttcom.enterprise.slack.com/files/U02FJ68CT7C/F0504EVEHEF/inband_timestamp.py)
