# protocol04 产物说明

- 输入/脚本：
  - `input/echo_server.py`：只监听 `127.0.0.1:18321` 的回显服务（固定 JSON，无敏感数据）；
  - `input/capture_live.sh`：自动从 `tshark -D` 挑 loopback，**BPF 仅 `tcp port 18321`**，
    `-a duration:5` 有界抓包，写 `artifacts/live.pcapng`。
- 运行（完整 cmd/rc/stdout 见 `run.json`）：
  1. `bash input/capture_live.sh`，rc=0（39 包 / 3 个 TCP 连接，全部在 18321 端口）；
  2. `rm -rf artifacts/streams` 后 `pcap-summary.py --file artifacts/live.pcapng --json --extract artifacts/streams --tshark-check`，rc=0；
  3. `tshark -Y 'http.request or http.response' -T fields …`，rc=0；
  4. `tshark -q -z conv,tcp`，rc=0。
- 产物：
  - `live.pcapng`：现场回环抓包（BPF 收敛，无其它进程流量）；
  - `pcap-summary.json`：39 包 / 6 方向性会话 / pcapng，`first_ts` 为 2026-10-21 epoch；
  - `streams/s00…s05.bin` + `frames.jsonl`：6 条方向性字节流与逐包 hex；
  - `http-fields.tsv`：3 请求 + 3 响应，method/uri/code/content-type/content-length/Set-Cookie/Authorization；
  - `conversations.txt`：3 条 TCP 会话（端口 57772→57774）。
- 结论：curl 未复用连接（3 个独立 `tcp.stream`），每会话 1 请求 1 响应；响应以 `Content-Length`
  （33/38/44 B）定界；`Set-Cookie: sid=lab-000N` 与 `X-Session-Id` 逐请求递增；`Bearer lab-token`
  是本案例自造的假值。
- 边界：无 TLS / keep-alive / 4xx-5xx 分支；未做重放与构造（只取证 + 分帧）。
  抓包必须带 BPF：本案例第一次未过滤时混入了同机其它进程的真实会话，已废弃重抓。
