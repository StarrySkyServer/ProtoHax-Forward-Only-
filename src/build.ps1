# 编译 ProtoHax 透明转发主程序为单文件 EXE。
# 内嵌 WinDivert.dll / WinDivert64.sys（x64），并附加 UAC 管理员清单。
# 产物：d:\CodeProject\ProtoHax\ProtoHaxForward.exe

param([string]$OutName = 'ProtoHaxForward.exe')

$ErrorActionPreference = 'Stop'

$srcDir   = $PSScriptRoot
$outDir   = Split-Path $srcDir -Parent
$wdDir    = 'C:\Users\27155\AppData\Local\Temp\windivert\WinDivert-2.2.2-A\x64'
$csc      = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$outExe   = Join-Path $outDir $OutName

$ico = Join-Path $srcDir 'app.ico'

foreach ($f in @($csc, (Join-Path $wdDir 'WinDivert.dll'), (Join-Path $wdDir 'WinDivert64.sys'), $ico)) {
    if (-not (Test-Path $f)) { throw "缺少依赖：$f" }
}

& $csc `
    /nologo `
    /target:winexe `
    /platform:x64 `
    /optimize+ `
    /out:$outExe `
    /win32icon:"$ico" `
    /win32manifest:"$srcDir\app.manifest" `
    /resource:"$wdDir\WinDivert.dll",WinDivert.dll `
    /resource:"$wdDir\WinDivert64.sys",WinDivert64.sys `
    /reference:System.dll `
    /reference:System.Drawing.dll `
    /reference:System.Windows.Forms.dll `
    "$srcDir\MainForm.cs" "$srcDir\Engines.cs" "$srcDir\Native.cs"

if ($LASTEXITCODE -ne 0) { throw "编译失败，退出码 $LASTEXITCODE" }
Write-Host ("编译成功 -> " + $outExe + "  (" + (Get-Item $outExe).Length + " 字节)")