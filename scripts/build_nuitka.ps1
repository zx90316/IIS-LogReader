#Requires -Version 5.1
<#
.SYNOPSIS
  使用 Nuitka 打包 Windows 發行版（預設採企業防毒友善的 standalone）。

.PARAMETER Mode
  standalone  - 資料夾發行（預設，強烈建議企業環境）
  onefile     - 單檔 exe（易被防毒啟發式誤判，不建議上公司電腦）

.PARAMETER CertThumbprint
  可選。若提供 Authenticode 憑證指紋，建置後以 signtool 簽章。

.EXAMPLE
  .\scripts\build_nuitka.ps1
  .\scripts\build_nuitka.ps1 -Mode standalone -CertThumbprint "ABC123..."
#>
param(
    [ValidateSet("standalone", "onefile")]
    [string]$Mode = "standalone",

    [string]$CertThumbprint = "",

    [switch]$SkipZip
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $Root

$VenvPython = Join-Path $Root ".venv\Scripts\python.exe"
if (Test-Path $VenvPython) {
    $Python = $VenvPython
} else {
    # CI / 未建立 venv：使用目前 PATH 的 python
    $cmd = Get-Command python -ErrorAction SilentlyContinue
    $Python = if ($cmd) { $cmd.Source } else { $null }
    if (-not $Python) {
        Write-Host "找不到 Python。請建立 .venv 或確保 python 在 PATH 中。" -ForegroundColor Red
        Write-Host "  python -m venv .venv"
        Write-Host "  .\.venv\Scripts\Activate.ps1"
        Write-Host "  pip install -r requirements.txt -r requirements-build.txt"
        exit 1
    }
    Write-Host "使用系統 Python：$Python" -ForegroundColor DarkYellow
}

if ($Mode -eq "onefile") {
    Write-Host ""
    Write-Host "警告：onefile 會在執行時解壓到 %%TEMP%%，企業防毒（Defender/趨勢/Symantec 等）" -ForegroundColor Yellow
    Write-Host "      常以「壓縮殼 / Dropper」啟發式誤判。公司環境請改用 standalone。" -ForegroundColor Yellow
    Write-Host ""
}

Write-Host "==> 安裝 / 更新建置依賴..." -ForegroundColor Cyan
& $Python -m pip install -q -r requirements.txt -r requirements-build.txt

$OutDir = Join-Path $Root "release"
$ProductName = "IIS-LogReader"
$Version = "1.0.0"
$Manifest = Join-Path $Root "packaging\app.manifest"

if (Test-Path $OutDir) {
    Write-Host "==> 清理舊的 release/ ..." -ForegroundColor Cyan
    Remove-Item -Recurse -Force $OutDir
}
New-Item -ItemType Directory -Path $OutDir | Out-Null

# 企業防毒友善參數：
# - 預設 standalone（不自解壓到 Temp）
# - 完整版本資源 / 公司名稱（降低未知發行者啟發式）
# - anti-bloat（減少異常匯入特徵）
# - 不使用 UPX / 執行期殼壓縮以外的額外加殼
# - 不強制打包 VC Runtime（改依賴系統已安裝環境，減少「夾帶 DLL」嫌疑）
$NuitkaArgs = @(
    "-m", "nuitka",
    "--standalone",
    "--enable-plugin=pyside6",
    "--windows-console-mode=disable",
    "--assume-yes-for-downloads",
    "--follow-imports",
    "--include-package=iis_log_reader",
    "--include-package=tzdata",
    "--include-data-files=app.config.example=app.config.example",
    "--include-windows-runtime-dlls=no",
    "--output-filename=$ProductName.exe",
    "--output-dir=$OutDir",
    "--product-name=IIS Log Reader",
    "--company-name=IIS-LogReader",
    "--file-description=IIS W3C Log Analyzer",
    "--file-version=$Version.0",
    "--product-version=$Version.0",
    "--copyright=Copyright (c) 2026 IIS-LogReader Contributors",
    "--trademarks=IIS Log Reader",
    "--remove-output",
    "--nofollow-import-to=tkinter",
    "--nofollow-import-to=unittest",
    "--nofollow-import-to=pytest"
)

if ($Mode -eq "onefile") {
    # 關閉 onefile 壓縮可略降「高熵加殼」特徵，但仍不如 standalone
    $NuitkaArgs += @(
        "--onefile",
        "--onefile-no-compression",
        '--onefile-tempdir-spec={CACHE_DIR}/IIS-LogReader/{VERSION}'
    )
    Write-Host "==> Nuitka onefile 打包（不建議企業環境）..." -ForegroundColor Cyan
} else {
    Write-Host "==> Nuitka standalone 打包（企業防毒建議模式）..." -ForegroundColor Cyan
}

$NuitkaArgs += "main.py"

Write-Host "Nuitka args: $($NuitkaArgs -join ' ')" -ForegroundColor DarkGray
& $Python @NuitkaArgs
if ($LASTEXITCODE -ne 0) {
    Write-Host "Nuitka 建置失敗 (exit $LASTEXITCODE)" -ForegroundColor Red
    exit $LASTEXITCODE
}

function Find-SdkTool {
    param([Parameter(Mandatory = $true)][string]$Name)
    $candidates = @(
        "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\$Name",
        "${env:ProgramFiles}\Windows Kits\10\bin\*\x64\$Name"
    )
    foreach ($pattern in $candidates) {
        $hit = Get-Item $pattern -ErrorAction SilentlyContinue |
            Sort-Object FullName -Descending |
            Select-Object -First 1
        if ($hit) { return $hit.FullName }
    }
    return $null
}

function Invoke-EmbedManifest {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path $Manifest)) { return }
    $mt = Find-SdkTool -Name "mt.exe"
    if (-not $mt) {
        Write-Host "找不到 mt.exe，略過嵌入 manifest（Nuitka 仍會帶預設 asInvoker）。" -ForegroundColor DarkYellow
        return
    }
    Write-Host "==> 嵌入 application manifest（asInvoker）..." -ForegroundColor Cyan
    & $mt -nologo -manifest $Manifest -outputresource:"$Path;1"
    if ($LASTEXITCODE -ne 0) {
        Write-Host "manifest 嵌入失敗（可忽略，不影響執行）" -ForegroundColor Yellow
    }
}

function Invoke-AuthenticodeSign {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not $CertThumbprint) { return }

    $signtool = Find-SdkTool -Name "signtool.exe"
    if (-not $signtool) {
        Write-Host "找不到 signtool.exe，略過簽章。請安裝 Windows SDK。" -ForegroundColor Yellow
        return
    }

    Write-Host "==> Authenticode 簽章：$Path" -ForegroundColor Cyan
    & $signtool sign `
        /sha1 $CertThumbprint `
        /fd SHA256 `
        /td SHA256 `
        /tr http://timestamp.digicert.com `
        /d "IIS Log Reader" `
        /du "https://github.com/zx90316/IIS-LogReader" `
        $Path
    if ($LASTEXITCODE -ne 0) {
        Write-Host "簽章失敗 (exit $LASTEXITCODE)" -ForegroundColor Red
        exit $LASTEXITCODE
    }
    & $signtool verify /pa $Path
}

$ReadmeRelease = @"
IIS Log Reader v$Version
========================

【執行】
  雙擊 IIS-LogReader.exe
  （standalone：請保留同目錄全部 DLL / 資料夾，勿只拷貝 exe）

【首次】
  同目錄會建立 app.config 與 cache/
  可複製 app.config.example 為 app.config 後再修改

【企業防毒】
  - 本發行版採 Nuitka standalone（非 onefile 自解壓）
  - 建議以公司程式碼簽章憑證簽章後再分發
  - 若仍被封鎖，請資安單位將發行雜湊加入允許清單，
    或至 Microsoft Defender 提交誤判：https://www.microsoft.com/wdsi/filesubmission

【隱私】
  分析含個資 Log 後請清理 cache/

授權：MIT
"@

$ExeToSign = $null
$PublishDir = $null

if ($Mode -eq "onefile") {
    $ExePath = Join-Path $OutDir "$ProductName.exe"
    if (-not (Test-Path $ExePath)) {
        $ExePath = Get-ChildItem -Path $OutDir -Filter "$ProductName.exe" -Recurse |
            Select-Object -First 1 -ExpandProperty FullName
    }
    Copy-Item (Join-Path $Root "app.config.example") (Join-Path $OutDir "app.config.example") -Force
    Set-Content -Path (Join-Path $OutDir "README.txt") -Value $ReadmeRelease -Encoding UTF8
    $ExeToSign = $ExePath
    $PublishDir = $OutDir
    Write-Host ""
    Write-Host "完成（onefile）：$ExePath" -ForegroundColor Green
} else {
    $DistDir = Join-Path $OutDir "main.dist"
    if (-not (Test-Path $DistDir)) {
        $DistDir = Get-ChildItem -Path $OutDir -Directory |
            Where-Object { $_.Name -like "*.dist" } |
            Select-Object -First 1 -ExpandProperty FullName
    }
    $FinalDir = Join-Path $OutDir $ProductName
    if (Test-Path $DistDir) {
        if (Test-Path $FinalDir) { Remove-Item -Recurse -Force $FinalDir }
        Rename-Item $DistDir (Split-Path $FinalDir -Leaf)
    }
    Copy-Item (Join-Path $Root "app.config.example") (Join-Path $FinalDir "app.config.example") -Force
    Set-Content -Path (Join-Path $FinalDir "README.txt") -Value $ReadmeRelease -Encoding UTF8
    $ExeToSign = Join-Path $FinalDir "$ProductName.exe"
    $PublishDir = $FinalDir
    Write-Host ""
    Write-Host "完成（standalone）：$ExeToSign" -ForegroundColor Green
    Write-Host "請整個資料夾一起發佈：$FinalDir" -ForegroundColor Green
}

if ($ExeToSign -and (Test-Path $ExeToSign)) {
    Invoke-EmbedManifest -Path $ExeToSign
    Invoke-AuthenticodeSign -Path $ExeToSign
}

if (-not $SkipZip -and $PublishDir -and (Test-Path $PublishDir)) {
    $zipPath = Join-Path $OutDir "$ProductName-v$Version-$Mode.zip"
    if (Test-Path $zipPath) { Remove-Item -Force $zipPath }
    Write-Host "==> 壓縮發行包：$zipPath" -ForegroundColor Cyan
    Compress-Archive -Path (Join-Path $PublishDir "*") -DestinationPath $zipPath -Force
    Write-Host "ZIP：$zipPath" -ForegroundColor Green
}

Write-Host ""
Write-Host "防毒提醒：未簽章的新軟體仍可能被攔截；公司環境請用簽章或白名單。" -ForegroundColor Yellow
