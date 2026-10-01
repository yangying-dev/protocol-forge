$ErrorActionPreference = "Stop"

$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Set-Location $Root

$Version = if ($env:PROTOCOLFORGE_VERSION) { $env:PROTOCOLFORGE_VERSION } else { "0.1.0" }
$Out = Join-Path $Root "artifacts\windows-x64"
$Stage = Join-Path $Out "ProtocolForge"
$Zip = Join-Path $Out "ProtocolForge-$Version-win-x86_64.zip"
$Dotnet = if ($env:DOTNET) { $env:DOTNET } else { "dotnet" }

if (Test-Path $Out) {
    Remove-Item -Recurse -Force $Out
}
New-Item -ItemType Directory -Force -Path $Stage | Out-Null

& $Dotnet restore ProtocolForge/ProtocolForge.csproj
& $Dotnet publish ProtocolForge/ProtocolForge.csproj `
    -c Release `
    -r win-x64 `
    --self-contained true `
    -p:PublishSingleFile=false `
    -p:IncludeNativeLibrariesForSelfExtract=false `
    -p:DebugType=None `
    -p:DebugSymbols=false `
    -o $Stage `
    --nologo `
    -warnaserror

if ($LASTEXITCODE -ne 0) {
    throw "dotnet publish failed with exit code $LASTEXITCODE"
}
if (-not (Test-Path (Join-Path $Stage "ProtocolForge.exe"))) {
    throw "ProtocolForge.exe was not produced"
}
Get-ChildItem -Path $Stage -Filter "*.pdb" -File -Recurse | Remove-Item -Force

# 混淆回填: OBFUSCATED_DLL 指向一个混淆后的 ProtocolForge.dll 则随包发布; 未设置则产出未混淆包。
$pkgDll = Join-Path $Stage "ProtocolForge.dll"
if ($env:OBFUSCATED_DLL) {
    if (-not (Test-Path $env:OBFUSCATED_DLL)) {
        throw "OBFUSCATED_DLL not found: $($env:OBFUSCATED_DLL)"
    }
    Copy-Item -Force $env:OBFUSCATED_DLL $pkgDll
    Write-Host "obfuscated: injected $($env:OBFUSCATED_DLL)"
} else {
    Write-Host "obfuscated: disabled (set OBFUSCATED_DLL to ship the obfuscated assembly)"
}
Write-Host "obfuscated: shipped DLL md5 = $((Get-FileHash -Algorithm MD5 $pkgDll).Hash.ToLowerInvariant())"

Copy-Item packaging/windows/CUSTOMER-INSTALL.txt (Join-Path $Stage "CUSTOMER-INSTALL.txt")
# Apache-2.0 §4(a) requires the license text to accompany every distributed copy,
# and the bundled MIT components require their license texts in all copies or
# substantial portions. Both must therefore land INSIDE the archive.
Copy-Item LICENSE (Join-Path $Stage "LICENSE")
Copy-Item THIRD-PARTY-NOTICES.md (Join-Path $Stage "THIRD-PARTY-NOTICES.md")
@"
ProtocolForge $Version
Target: Windows 10/11 x64
Publish: multi-file self-contained .NET 8
Build date: $(Get-Date -Format yyyy-MM-dd)
Customer dependency: Wireshark/tshark >= 2.6.0; customer-installed Npcap supported, not bundled
License: Apache-2.0 (see LICENSE); third-party attributions in THIRD-PARTY-NOTICES.md
Data: no production PCAP, private key, or payment credentials are included
"@ | Set-Content -Encoding UTF8 (Join-Path $Stage "RELEASE-MANIFEST.txt")

Compress-Archive -Path $Stage -DestinationPath $Zip -CompressionLevel Optimal
$digest = (Get-FileHash -Algorithm SHA256 $Zip).Hash.ToLowerInvariant()
"$digest  $(Split-Path $Zip -Leaf)" | Set-Content -Encoding ASCII (Join-Path $Out "SHA256SUMS")

Write-Host "Windows multi-file package:"
Write-Host "  $Zip"
Write-Host "  $(Join-Path $Out 'SHA256SUMS')"
