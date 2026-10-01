# Linux Packaging

ProtocolForge Linux 商业交付使用**多文件** self-contained 发布，生成：

- `ProtocolForge-<version>-linux-x86_64.AppImage`
- `protocolforge_<version>_amd64.deb`
- `SHA256SUMS`

macOS 打包暂不属于本目录范围。

## 本机构建

```bash
./packaging/linux/publish-linux.sh
```

默认输出到：

```text
artifacts/linux-x64/
```

需要：

- .NET 8 SDK；
- `tshark`（运行时依赖，不打包进程序）；
- ImageMagick `convert` 或 `magick`；
- `appimagetool`；
- `dpkg-deb`、`fakeroot`。

如果本机暂时没有 AppImage 工具，可以先只构建 deb：

```bash
SKIP_APPIMAGE=1 ./packaging/linux/publish-linux.sh
```

CI 会自动下载 `appimagetool` 并生成两种产物。

## 随包发布混淆版

打包脚本默认产出**未混淆**包。如果你自行产出了混淆后的 `ProtocolForge.dll`，设置 `OBFUSCATED_DLL` 指向它：

```bash
OBFUSCATED_DLL=/path/to/ProtocolForge.dll \
  ./packaging/linux/publish-linux.sh
```

- `OBFUSCATED_DLL` 指向的文件不存在时脚本**硬失败**并打印该路径；
- 无论是否启用，脚本都会打印随包 `ProtocolForge.dll` 的 md5，便于核对客户拿到的到底是哪一版；
- 混淆在 `dotnet publish` 之后、组装 AppDir/deb 之前生效，因此 AppImage 与 deb 内嵌的是同一份混淆程序集；
- 不设该变量时行为与从前完全一致，CI 亦如此（CI 不产出混淆包）。

## 多文件和用户数据

发布目录是程序文件：

```text
/opt/ProtocolForge/                 # deb 安装目录
ProtocolForge.AppDir/usr/bin/      # AppImage 内部程序目录
```

用户数据不放入安装目录：

```text
~/.config/ProtocolForge/            # 设置、布局
~/.local/share/ProtocolForge/logs/  # trace.log
```

卸载 deb 不会删除上述用户数据。重新安装或升级后设置与布局仍然保留。

## tshark 和发包权限

安装包依赖 `tshark`，建议客户单独安装 Wireshark/tshark。找不到 tshark 时应用进入只读模式。

Linux 原始发包通常需要 root 或 `CAP_NET_RAW`。打包脚本不会自动给程序授予 raw socket 权限，避免安装后立即扩大安全边界；权限配置应按客户系统和组织策略单独处理。
