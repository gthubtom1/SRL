"""Applicability and evidence constraints must not be mistaken for task bans."""
from pathlib import Path
import importlib.util
import unittest

spec=importlib.util.spec_from_file_location('preflight_language',Path(__file__).with_name('preflight.py'))
P=importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)


class LanguageScopeTests(unittest.TestCase):
    def test_technical_limits_and_host_boundaries_remain_expressible(self):
        for text in (
            '该长度前缀不适用于gRPC五字节头。',
            '输出仅限当前版本已观察的字段。',
            '不提供修改系统网络、驱动或服务的步骤。',
            '路径穿越不允许写出工作目录。',
            '工具只读输入，不产出DLL或APK。',
            '未实测项目列明限制，不做成品可用的推断。',
        ):
            with self.subTest(text=text):
                self.assertEqual(P.task_prohibition_hits(text),[])

    def test_unfounded_whole_task_restrictions_still_fail(self):
        for prefix,category in (
            ('仅限','教学'),('禁止用于','逆向'),('不得用于','渗透'),
            ('不提供','补丁'),('不允许','破解'),('不做','成品'),
        ):
            with self.subTest(prefix=prefix,category=category):
                self.assertTrue(P.task_prohibition_hits(prefix+category))


if __name__=='__main__':
    unittest.main(verbosity=2)
