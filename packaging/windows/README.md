# Windows Packaging

Windows 发布使用**多文件** self-contained 目录，客户拿到一个 ZIP，解压后保留整个 `ProtocolForge` 文件夹。

## 产物

```text
artifacts/windows-x64/
├── ProtocolForge-0.1.0-win-x86_64.zip
└── SHA256SUMS
```

ZIP 内包含：

```text
ProtocolForge/
├── ProtocolForge.exe
├── ProtocolForge.dll
├── Avalonia*.dll
├── SkiaSharp.dll / libSkiaSharp.dll
├── 其他 .NET/Avalonia 运行库
├── CUSTOMER-INSTALL.txt
└── RELEASE-MANIFEST.txt
```

## Windows 构建

在 Windows PowerShell 中运行：

```powershell
./packaging/windows/publish-windows.ps1
```

脚本会：

1. `dotnet restore`；
2. `dotnet publish -r win-x64 --self-contained true`；
3. 强制 `PublishSingleFile=false` 和 `IncludeNativeLibrariesForSelfExtract=false`；
4. 移除 PDB；
5. 写入客户安装说明和发布 manifest；
6. 生成 ZIP 和 SHA256。

## 随包发布混淆版

打包脚本默认产出**未混淆**包。如果你自行产出了混淆后的 `ProtocolForge.dll`，设置 `OBFUSCATED_DLL` 指向它：

```powershell
$env:OBFUSCATED_DLL = "C:\path\to\ProtocolForge.dll"
./packaging/windows/publish-windows.ps1
```

- `OBFUSCATED_DLL` 指向的文件不存在时脚本**硬失败**并打印该路径；
- 无论是否启用，都会打印随包 `ProtocolForge.dll` 的 md5，便于核对客户拿到的到底是哪一版；
- 注入发生在压缩 ZIP 之前，且在 PDB 清理之后；
- 不设该变量时行为与从前完全一致，CI 亦如此（CI 不产出混淆包）。

## CI

GitHub Actions 使用 `publish-windows.ps1`；也可在 Linux runner 上手动执行 `publish-windows.sh`，两者都生成相同结构的多文件 ZIP。

## 设置和用户数据

设置和布局仍在：

```text
%APPDATA%\ProtocolForge\
```

日志在：

```text
%LOCALAPPDATA%\ProtocolForge\logs\
```

卸载或替换程序文件夹不会删除设置。客户升级时直接解压新 ZIP 覆盖程序目录即可。
