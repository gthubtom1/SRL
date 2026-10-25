# Seep Reverse Lab - 一键测试入口（唯一入口）
#   powershell -File check.ps1            -> 全量（8 套件）
#   powershell -File check.ps1 -Fast      -> 提交前快跑
#   powershell -File check.ps1 -Detailed  -> 详细模式（本入口补的，check.py 没有 --verbose）：
#        ① 先打套件清单（check.py --list：跑哪些、fast 还是 full、为什么有这条）
#        ② 跑完后按 PASS/FAIL 重排一份逐套件表（失败的标红）
#        ③ 完整 stdout 落盘并把日志路径打出来
#        ④ 结尾打「结论 / 证据 / 失败 / 下一步」四栏看板
#   退出码始终是 check.py 的退出码（0=全过，1=有失败），-Detailed 不改判定。
param([switch]$Fast, [switch]$Detailed)
# PS 5.1 默认按控制台代码页（中文机器=GBK）解码子进程输出，而 python 侧固定输出 UTF-8
# （check.py / 各子脚本都 reconfigure 成 utf-8）。不先对齐就会把中文按 GBK 解成乱码，
# -Detailed 的日志与逐套件重排表会直接坏掉（同一坑 uninstall.ps1 已踩过并修过）。
try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    $OutputEncoding = [System.Text.Encoding]::UTF8
} catch { }
$root = $PSScriptRoot
$checkPy = Join-Path $root 'Tool\scripts\check.py'
$args2 = @()
if ($Fast) { $args2 += '--fast' }

if (-not $Detailed) {
    & python $checkPy @args2
    exit $LASTEXITCODE
}

# ------------------------------------------------------------------ 详细模式
# 说明：check.py 只把每个套件的末行摘要打出来（子进程 stdout 被它吃掉）。
# 它的详细能力只有 --list（套件清单），所以这里先跑 --list，
# 再把 check.py 的完整 stdout 落盘 + 逐套件重排，让"哪一条红了、去哪看"一眼可见。
Write-Host '=== 套件清单（python Tool/scripts/check.py --list）===' -ForegroundColor Cyan
& python $checkPy --list
Write-Host ''
Write-Host '=== 逐套件结果 ===' -ForegroundColor Cyan

$logPath = Join-Path ([System.IO.Path]::GetTempPath()) ("seep-check-" + (Get-Date -Format 'yyyyMMdd-HHmmss') + ".log")
$lines = @()
& python $checkPy @args2 | ForEach-Object {
    $line = "$_"
    $lines += $line
    if ($line -match '^FAIL') { Write-Host $line -ForegroundColor Red }
    elseif ($line -match '^PASS') { Write-Host $line -ForegroundColor Green }
    else { Write-Host $line }
}
$rc = $LASTEXITCODE

try {
    [System.IO.File]::WriteAllLines($logPath, $lines, (New-Object System.Text.UTF8Encoding $false))
} catch {
    $logPath = '(日志写入失败: ' + $_.Exception.Message + ')'
}

$failed = @()
$passed = 0
foreach ($line in $lines) {
    if ($line -match '^(PASS|FAIL)\s+(\S+)') {
        if ($matches[1] -eq 'FAIL') { $failed += $matches[2] } else { $passed++ }
    }
}

Write-Host ''
Write-Host ('--- 四栏看板 ' + ('-' * 44)) -ForegroundColor White
if ($rc -eq 0) {
    Write-Host '结论  : PASS 全部通过' -ForegroundColor Green
} else {
    Write-Host ('结论  : FAIL（失败 ' + $failed.Count + ' 个套件：' + ($failed -join ', ') + '）') -ForegroundColor Red
}
Write-Host ('证据  : 通过 ' + $passed + ' 个；完整输出 -> ' + $logPath)
if ($failed.Count -gt 0) {
    Write-Host ('失败  : ' + ($failed -join ', '))
    Write-Host ('下一步: 单个复跑 python Tool/scripts/check.py --list 里对应的脚本；不许只看 PASS 就交付')
} else {
    Write-Host '失败  : 无'
    Write-Host '下一步: 全量 check.py（不带 --fast）确认后再提交'
}
Write-Host ('-' * 70) -ForegroundColor White

exit $rc
