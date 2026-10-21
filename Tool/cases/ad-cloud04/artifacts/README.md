# ad-cloud04 artifacts

离线五类判定复算（Kerberoast / AS-REP / ADCS / 委派 / K8s RBAC），输入是手写证据包夹具。

```bash
cd Tool/cases/ad-cloud04
python ../../skill/ad-cloud/scripts/ad-repro.py --input input/bundle.json --json > artifacts/run.json  # rc=0
```

预期 `summary={"candidate": 5}`：每条都有路径条件，但缺破解/票据/auth/宿主证据。
