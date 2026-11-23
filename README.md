磁盘清理工具 源码包
=====================

包含两个可独立使用的实现：
1) 独立版（Windows 桌面程序，C# WinForms，单个 exe）
2) DSH 插件（DeepSeek Harness 插件，JavaScript）

两者共用同一套扫描规则与报告格式，全部只读，不删除/不移动任何文件。

目录结构
--------
独立版\DiskCleanup-独立版\
    Program.cs        完整源码（约 1500 行，含扫描器、规则、报告、GUI、CLI）
    app.manifest      DPI 感知与兼容性清单
    使用说明.txt      给最终用户的使用说明
插件\dsh-disk-cleanup\
    package.json      插件清单（dsh.bundle / dsh.client 声明）
    cordis.patch.yml  插件装配补丁
    index.js          宿主入口：disk_cleanup_scan 工具 + HTTP 接口
    client.js         右侧栏「磁盘扫描」面板
    lib/scan.js       扫描引擎与分类规则
    lib/report.js     报告生成（MD/HTML/CSV/JSON）
    lib/worker.js     worker 线程入口
    locale/           中英文插件信息
    icon.svg          插件图标
    README.md         插件详细说明
build.bat             一键编译独立版（调用系统自带的 csc.exe）

编译独立版
----------
环境要求：Windows 10/11，自带 .NET Framework 4.x（无需安装 SDK、Node.js）
双击 build.bat，或在命令行执行：

  %WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe /nologo /target:winexe /optimize+ ^
    /win32manifest:app.manifest /out:DiskCleanup.exe ^
    /r:System.dll /r:System.Core.dll /r:System.Windows.Forms.dll /r:System.Drawing.dll Program.cs

编译产物 DiskCleanup.exe 约 53 KB，可直接分发。
命令行模式：DiskCleanup.exe --scan --path "C:\" --out "D:\reports\c" --threshold 300 --depth 2

安装插件
--------
把 插件\dsh-disk-cleanup 文件夹放到任意位置，在 DSH 的设置 → 插件 → 添加插件中选择该文件夹，
安装后刷新页面；右侧栏会出现「磁盘扫描」页签。需要 DSH 0.2.2 及以上。

扫描规则
--------
- 目录规则 35 条：Windows 更新/日志/WinSxS\Temp/servicing、NVIDIA 着色器缓存、Edge/Chrome 缓存、
  WeChat/QQ 文件、游戏录像（ACLOS）、WPS 缓存、Downloads、UWP Packages、LeAppStore\cicada、
  webhelper/SakuraFrp/QiYi/xfolder 等
- 文件规则：hiberfil.sys、pagefile/swapfile、MEMORY.DMP、setupact.log、根目录大体积 *.tmp
- 分级：A 低风险 / B 需确认 / C 先核实 / D 勿删（WinSxS、Installer、DriverStore、Package Cache、
  assembly、System Volume Information 只列出不清理）
- 报告：Markdown、HTML、CSV、JSON；输出到 文档\DSH-Scan\<盘符>-<时间>\

性能参考
--------
扫描耗时取决于文件数量、磁盘性能、目录权限和杀毒软件实时扫描强度。

说明
----
- 源码仅用于本地磁盘清理用途；扫描结果基于路径与名称规则，不做病毒查杀。
- 报告中的目录大小按逻辑长度累加，含硬链接的 WinSxS 等可能偏大。
