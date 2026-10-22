param(
    [string]$ImagePath,
    [string]$Out,
    [string]$Language = 'zh-Hans-CN',
    [switch]$SelfTest,
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$Rest = @()
)

# 同时接受 `--self-test`（配方/CI 的通用写法）与 `-SelfTest`。
if ($Rest -contains '--self-test' -or $Rest -contains '-self-test') { $SelfTest = $true }
$Rest = @($Rest | Where-Object { $_ -ne '--self-test' -and $_ -ne '-self-test' })

try {
    [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
    $OutputEncoding = New-Object System.Text.UTF8Encoding($false)
} catch { }

# temp_ocr.ps1 -- 本地 Windows.Media.Ocr 识别（离线，不调外部识别）。
#
# 用法：
#   powershell -File Tool/scripts/temp_ocr.ps1 -ImagePath work/<case>/captcha.png
#   powershell -File Tool/scripts/temp_ocr.ps1 -ImagePath captcha.png -Out work/<case>/ocr.json
#   pwsh -File Tool/scripts/temp_ocr.ps1 --self-test
#
# 行为（配方 captcha-handling 第 2 步判据）：
#   成功 → rc=0，把 {"ok":true,"text":...,"confidence":...} 写入 ocr.json
#          （默认 <图片同目录>/ocr.json，可用 -Out 覆盖），并把文本打到 stdout（兼容旧用法）。
#   失败 → rc=2，stdout 打一行 {"ok":false,"blocked_at":"ocr-failed","reason":...}。
#
# confidence 说明：Windows.Media.Ocr 不暴露引擎置信度，这里按识别出的有效字符数
# 给一个确定性的启发值（0.45 短文本 / 0.60+0.01*chars，上限 0.95），用于分档：
# <0.35 换路（人工/换图），0.35-0.6 复核，>=0.6 可用。别把它当概率。

$ErrorActionPreference = 'Stop'

function New-JsonFile {
    param([string]$Path, [System.Collections.IDictionary]$Obj)
    $parent = Split-Path -Parent $Path
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }
    $json = $Obj | ConvertTo-Json -Compress -Depth 6
    $enc = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $json + "`n", $enc)
    return $json
}

function Get-OcrConfidence {
    param([string]$Text)
    $chars = ($Text -replace '\s', '').Length
    if ($chars -eq 0) { return 0.0 }
    if ($chars -lt 4) { return 0.45 }
    return [Math]::Round([Math]::Min(0.95, 0.60 + 0.01 * $chars), 3)
}

function Fail-Ocr {
    param([string]$Reason, [int]$Code = 2)
    $obj = [ordered]@{
        ok         = $false
        blocked_at = 'ocr-failed'
        reason     = $Reason
        image      = $ImagePath
        out        = $Out
    }
    ($obj | ConvertTo-Json -Compress -Depth 5)
    exit $Code
}

function Invoke-OcrSelfTest {
    $checks = [ordered]@{}
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("seep-ocr-selftest-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $tmp | Out-Null
    try {
        # 1) 成功路径的写盘格式：text / confidence 必须在 ocr.json 里
        $jsonPath = Join-Path $tmp 'ocr.json'
        $payload = [ordered]@{
            ok         = $true
            text       = 'HELLO 1234'
            confidence = (Get-OcrConfidence 'HELLO 1234')
            lines      = @('HELLO 1234')
            image      = (Join-Path $tmp 'fake.png')
            out        = $jsonPath
        }
        New-JsonFile -Path $jsonPath -Obj $payload | Out-Null
        $checks['ocr-json-written'] = (Test-Path -LiteralPath $jsonPath)
        $back = Get-Content -LiteralPath $jsonPath -Raw | ConvertFrom-Json
        $checks['ocr-json-text'] = ($back.text -eq 'HELLO 1234')
        $checks['ocr-json-confidence'] = ([double]$back.confidence -ge 0.6)
        $checks['confidence-short-text'] = ((Get-OcrConfidence 'A') -eq 0.45)
        $checks['confidence-empty'] = ((Get-OcrConfidence '   ') -eq 0.0)

        # 2) 失败路径：缺图必须 rc=2 且输出 {ok:false, blocked_at:"ocr-failed"}
        $missing = Join-Path $tmp 'nope.png'
        $raw = & $PSCommandPath -ImagePath $missing -Out (Join-Path $tmp 'nope.json') 2>&1 | Out-String
        $checks['missing-image-rc2'] = ($LASTEXITCODE -eq 2)
        $failed = $null
        try { $failed = $raw | ConvertFrom-Json } catch { $failed = $null }
        $checks['missing-image-json'] = ($null -ne $failed -and $failed.ok -eq $false -and $failed.blocked_at -eq 'ocr-failed')
    } finally {
        Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }
    $bad = @($checks.Keys | Where-Object { -not $checks[$_] })
    $report = [ordered]@{
        ok       = ($bad.Count -eq 0)
        tool     = 'temp_ocr.ps1'
        checks   = $checks.Count
        failures = $bad
    }
    ($report | ConvertTo-Json -Compress -Depth 5)
    if ($bad.Count -eq 0) { exit 0 } else { exit 2 }
}

if ($SelfTest) {
    Invoke-OcrSelfTest
}

if ($Rest.Count -gt 0) {
    Fail-Ocr ('未知参数: ' + ($Rest -join ' ')) 2
}

if (-not $ImagePath) {
    $ImagePath = ''
    $Out = ''
    Fail-Ocr '缺少 -ImagePath' 2
}
if (-not (Test-Path -LiteralPath $ImagePath -PathType Leaf)) {
    Fail-Ocr ("图片不存在: " + $ImagePath) 2
}
if (-not $Out) {
    $dir = Split-Path -Parent $ImagePath
    if (-not $dir) { $dir = '.' }
    $Out = Join-Path $dir 'ocr.json'
}

try {
    Add-Type -AssemblyName System.Runtime.WindowsRuntime
    $asTaskGeneric = [System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' } | Select-Object -First 1

    function Await($WinRtTask, $ResultType) {
        $asTask = $asTaskGeneric.MakeGenericMethod($ResultType)
        $netTask = $asTask.Invoke($null, @($WinRtTask))
        $netTask.Wait(-1) | Out-Null
        $netTask.Result
    }

    [Windows.Globalization.Language, Windows.Globalization, ContentType=WindowsRuntime] | Out-Null
    [Windows.Graphics.Imaging.BitmapDecoder, Windows.Graphics.Imaging, ContentType=WindowsRuntime] | Out-Null
    [Windows.Media.Ocr.OcrEngine, Windows.Media.Ocr, ContentType=WindowsRuntime] | Out-Null
    [Windows.Storage.StorageFile, Windows.Storage, ContentType=WindowsRuntime] | Out-Null

    $engine = $null
    try {
        $lang = [Windows.Globalization.Language]::new($Language)
        $engine = [Windows.Media.Ocr.OcrEngine]::TryCreateFromLanguage($lang)
    } catch {
        $engine = $null
    }
    if ($null -eq $engine) {
        $engine = [Windows.Media.Ocr.OcrEngine]::TryCreateFromUserProfileLanguages()
    }
    if ($null -eq $engine) {
        Fail-Ocr ("没有可用的 OCR 引擎（语言: " + $Language + "）；Windows 设置里装 OCR 语言包") 2
    }

    $file = Await ([Windows.Storage.StorageFile]::GetFileFromPathAsync((Resolve-Path -LiteralPath $ImagePath).Path)) ([Windows.Storage.StorageFile])
    $stream = Await ($file.OpenAsync([Windows.Storage.FileAccessMode]::Read)) ([Windows.Storage.Streams.IRandomAccessStream])
    $decoder = Await ([Windows.Graphics.Imaging.BitmapDecoder]::CreateAsync($stream)) ([Windows.Graphics.Imaging.BitmapDecoder])
    $bitmap = Await ($decoder.GetSoftwareBitmapAsync()) ([Windows.Graphics.Imaging.SoftwareBitmap])
    $result = Await ($engine.RecognizeAsync($bitmap)) ([Windows.Media.Ocr.OcrResult])

    $lines = @($result.Lines | ForEach-Object { $_.Text })
    $text = ($lines -join "`n").Trim()
    if (-not $text) {
        Fail-Ocr '识别结果为空（图里没有可识别文本）' 2
    }
    $confidence = Get-OcrConfidence $text
    $payload = [ordered]@{
        ok         = $true
        text       = $text
        confidence = $confidence
        lines      = $lines
        image      = $ImagePath
        out        = $Out
        engine     = 'windows.media.ocr'
        language   = [string]$engine.RecognizerLanguage.LanguageTag
    }
    New-JsonFile -Path $Out -Obj $payload | Out-Null
    $lines | ForEach-Object { $_ }
    exit 0
} catch {
    Fail-Ocr ($_.Exception.Message) 2
}
