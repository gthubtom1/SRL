"""入口：读取 YAML 配置（PyYAML 的 import 名是 yaml）。"""
import yaml


def load(path):
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)
