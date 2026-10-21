# ad-cloud03 artifacts

真实 Windows Security 事件日志（100 条，已脱敏）经 `ad-repro.py --kind windows-events` 复算。

```bash
MSYS_NO_PATHCONV=1 wevtutil qe Security \
  '/q:*[System[(EventID=4624 or EventID=4625 or EventID=4672 or EventID=4768 or EventID=4769 or EventID=4648)]]' \
  /f:xml /c:100 /rd:true > /tmp/sec2.xml                       # rc=0
python Tool/skill/ad-cloud/scripts/ad-repro.py \
  --extract-evtx-xml /tmp/sec2.xml --out input/security-events.json  # rc=0
cd Tool/cases/ad-cloud03
python ../../skill/ad-cloud/scripts/ad-repro.py \
  --kind windows-events --input input/security-events.json --json > artifacts/run.json  # rc=0
```

`run.json` 的 sha256 见 `case.json`。原始 XML 不落仓库；用户名/主机/IP 已替换为 USER/HOST/IP。
