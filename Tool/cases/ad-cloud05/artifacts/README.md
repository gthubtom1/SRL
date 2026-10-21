# ad-cloud05 artifacts

离线 IAM 策略评估（身份策略 + permissions boundary），输入是手写策略夹具。

```bash
cd Tool/cases/ad-cloud05
python ../../skill/ad-cloud/scripts/cloud-iam-eval.py --input input/policy.json \
  --action iam:CreatePolicyVersion --resource arn:aws:iam::123456789012:policy/demo > artifacts/run.json  # rc=0
python ../../skill/ad-cloud/scripts/cloud-iam-eval.py --input input/policy.json \
  --action s3:GetObject --resource arn:aws:s3:::demo-bucket/secret/a.txt > artifacts/run-deny.json  # rc=0
```

第一次 `decision=allow` 并列出 privesc 组合；第二次 `decision=deny`（显式 Deny 优先）。
