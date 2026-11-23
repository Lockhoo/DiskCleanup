// DiskCleanup.exe - 独立版磁盘清理扫描器（无需安装智能体）
// 编译：csc /target:winexe /out:DiskCleanup.exe /r:System.dll /r:System.Core.dll /r:System.Windows.Forms.dll /r:System.Drawing.dll Program.cs
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace DiskCleanup
{
    internal static class Program
    {
        [STAThread]
        private static int Main(string[] args)
        {
            if (args.Length > 0 && (args[0] == "--scan" || args[0] == "/scan"))
            {
                try { return Cli.Run(args); }
                catch (Exception ex)
                {
                    try { File.AppendAllText(Path.Combine(Path.GetTempPath(), "disk-cleanup-cli-error.log"), ex.ToString()); }
                    catch { }
                    return 2;
                }
            }
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
            return 0;
        }
    }

    public class Candidate
    {
        public string Path;
        public string Key;
        public string Category;
        public string Risk;
        public string Advice;
        public string Note;
        public long Bytes;
    }

    public class FileRec
    {
        public string Path;
        public string Key;
        public long Bytes;
        public DateTime MTime;
    }

    public class DirRec
    {
        public string Key;
        public long Bytes;
        public int Files;
    }

    public class ProgressInfo
    {
        public long Dirs;
        public long Files;
        public long Bytes;
        public string CurrentDir;
    }

    public class ScanResult
    {
        public string Root;
        public DateTime ScannedAt;
        public double ElapsedSec;
        public long Files;
        public long Dirs;
        public long Bytes;
        public long Errors;
        public long VolumeTotal;
        public long VolumeFree;
        public int CandidateTotal;
        public int Depth;
        public int LargeFileMb;
        public List<DirRec> TopDirs = new List<DirRec>();
        public List<DirRec> DirsAtDepth = new List<DirRec>();
        public List<FileRec> Large = new List<FileRec>();
        public List<Candidate> Candidates = new List<Candidate>();
        public List<Candidate> Keep = new List<Candidate>();
        public Dictionary<string, long> Ext = new Dictionary<string, long>();
    }

    public class Rule
    {
        public string Pattern;
        public string Category;
        public string Risk;
        public string Advice;
        public string Note;
        public Rule(string pattern, string category, string risk, string advice, string note)
        {
            Pattern = pattern; Category = category; Risk = risk; Advice = advice; Note = note;
        }
    }

    public static class Rules
    {
        public static readonly Rule[] DirRules = new Rule[]
        {
            new Rule(@"^windows/softwaredistribution/download$", "更新缓存", "safe", "可删除", "Windows 更新下载缓存，删前先停止 wuauserv 服务"),
            new Rule(@"^windows/softwaredistribution/deliveryoptimization$", "更新缓存", "safe", "可删除", "传递优化缓存"),
            new Rule(@"^windows/logs$", "日志", "safe", "可删除", "系统日志"),
            new Rule(@"^windows/panther$", "日志", "safe", "可删除", "系统升级日志（setupact.log 等）"),
            new Rule(@"^windows/winsxs/temp$", "系统缓存", "safe", "建议用磁盘清理", "组件存储临时文件"),
            new Rule(@"^windows/servicing/sessions$", "系统缓存", "safe", "建议用磁盘清理", "更新会话数据"),
            new Rule(@"^windows/temp$", "临时文件", "safe", "可删除", "系统临时目录"),
            new Rule(@"^windows/prefetch$", "系统缓存", "safe", "可删除", "预读取缓存，自动重建"),
            new Rule(@"^windows/minidump$", "崩溃转储", "safe", "可删除", "蓝屏小型转储"),
            new Rule(@"^windows/livekernelreports$", "崩溃转储", "safe", "可删除", "内核实时报告"),
            new Rule(@"^programdata/nvidia corporation/(downloader|nv_cache)$", "显卡缓存", "safe", "可删除", "NVIDIA 驱动下载/着色器缓存"),
            new Rule(@"^programdata/microsoft/windows/(wer|deliveryoptimization)$", "系统缓存", "safe", "可删除", "错误报告/传递优化缓存"),
            new Rule(@"^programdata/lenovo/leappstore/cicada$", "软件缓存", "safe", "可删除", "联想应用商店下载缓存（哈希命名安装包）"),
            new Rule(@"^users/[^/]+/appdata/local/temp$", "临时文件", "safe", "可删除", "用户临时目录"),
            new Rule(@"^users/[^/]+/appdata/local/crashdumps$", "崩溃转储", "safe", "可删除", "应用崩溃转储"),
            new Rule(@"^users/[^/]+/appdata/local/microsoft/windows/(explorer|inetcache|webcache)$", "缓存", "safe", "可删除", "缩略图/IE/系统缓存"),
            new Rule(@"^users/[^/]+/appdata/local/nvidia/(dxcache|glcache)$", "显卡缓存", "safe", "可删除", "着色器缓存，进游戏自动重建"),
            new Rule(@"^users/[^/]+/appdata/locallow/nvidia$", "显卡缓存", "safe", "可删除", "按驱动版本分的着色器缓存"),
            new Rule(@"^users/[^/]+/appdata/local/d3dscache$", "显卡缓存", "safe", "可删除", "DirectX 着色器缓存"),
            new Rule(@"^users/[^/]+/appdata/local/jetbrains$", "IDE 缓存", "safe", "可删除", "JetBrains 索引缓存，可在 IDE 内清理"),
            new Rule(@"^users/[^/]+/appdata/local/google/androidstudio[^/]*$", "IDE 缓存", "safe", "可删除", "Android Studio 索引缓存"),
            new Rule(@"^users/[^/]+/appdata/local/steam/htmlcache$", "缓存", "safe", "可删除", "Steam 网页缓存"),
            new Rule(@"^users/[^/]+/appdata/local/[^/]+-updater$", "安装包残留", "safe", "可删除", "软件更新器下载的安装包"),
            new Rule(@"^users/[^/]+/appdata/local/(microsoft/edge|google/chrome)/user data/[^/]+/(cache|code cache|gpucache|shadercache)$", "浏览器缓存", "safe", "可删除", "浏览器缓存，勿删整个浏览器数据目录"),
            new Rule(@"^users/[^/]+/documents/wechat files$", "个人数据", "review", "需确认", "微信聊天文件，建议在微信内清理"),
            new Rule(@"^users/[^/]+/documents/tencent files$", "个人数据", "review", "需确认", "QQ 接收文件，建议在 QQ 内清理"),
            new Rule(@"^users/[^/]+/appdata/aclos$", "游戏录像", "review", "需确认", "游戏自动录制的高光片段（mp4）"),
            new Rule(@"^users/[^/]+/appdata/roaming/(kingsoft|wps)$", "软件缓存", "review", "需确认", "WPS 缓存/备份/插件"),
            new Rule(@"^users/[^/]+/downloads$", "下载目录", "review", "需确认", "下载文件，含旧安装包与个人文件"),
            new Rule(@"^users/[^/]+/appdata/local/packages$", "应用缓存", "review", "逐个清理", "UWP 应用缓存，建议在 设置-应用 中清理"),
            new Rule(@"^programdata/webhelper[^/]*$", "来源不明", "unknown", "先核实", "疑似捆绑安装器残留（CEF 内核）"),
            new Rule(@"^programdata/sakurafrp[^/]*$", "来源不明", "unknown", "先核实", "内网穿透工具，不用建议卸载"),
            new Rule(@"^programdata/qiyi$", "软件残留", "review", "可删除", "爱奇艺 P2P 组件残留"),
            new Rule(@"^users/[^/]+/appdata/roaming/iqiyi video$", "软件残留", "review", "可删除", "爱奇艺残留缓存"),
            new Rule(@"^programdata/(xfolder|tianxiang|whesvc|dbg)$", "来源不明", "unknown", "先核实", "来源不明的小型残留目录")
        };

        public static readonly string[,] KeepDirs = new string[,]
        {
            { "windows/winsxs", "组件存储，只能用 DISM /StartComponentCleanup 清理" },
            { "windows/installer", "MSI 缓存，删除会导致软件无法卸载/修复" },
            { "windows/system32/driverstore", "驱动仓库，删除会导致驱动失效" },
            { "programdata/package cache", "安装包缓存，卸载/修复软件时需要" },
            { "windows/assembly", ".NET 程序集缓存" },
            { "system volume information", "系统还原点，需管理员权限处理" }
        };

        public static readonly System.Text.RegularExpressions.Regex GenericCache =
            new System.Text.RegularExpressions.Regex(@"/cache$|/code cache$|/gpucache$|/shadercache$|/cache_data$");
        public static readonly System.Text.RegularExpressions.Regex GenericLog =
            new System.Text.RegularExpressions.Regex(@"/logs?$");

        public static Rule ClassifyDir(string norm)
        {
            foreach (Rule r in DirRules)
            {
                if (System.Text.RegularExpressions.Regex.IsMatch(norm, r.Pattern)) return r;
            }
            if ((norm.StartsWith("users/") && norm.Contains("/appdata/")) || norm.StartsWith("programdata/"))
            {
                if (GenericCache.IsMatch(norm)) return new Rule("", "通用缓存", "safe", "可删除", "应用缓存目录（通用规则匹配）");
                if (GenericLog.IsMatch(norm)) return new Rule("", "日志", "safe", "可删除", "应用日志目录（通用规则匹配）");
            }
            return null;
        }

        public static Rule ClassifyFile(string norm, long size)
        {
            string baseName = norm;
            int slash = norm.LastIndexOf('/');
            if (slash >= 0) baseName = norm.Substring(slash + 1);
            if (norm == "hiberfil.sys") return new Rule("", "休眠文件", "review", "可选", "管理员执行 powercfg /h off 可释放，会失去休眠/快速启动");
            if (baseName == "pagefile.sys" || baseName == "swapfile.sys") return new Rule("", "系统文件", "keep", "勿删", "页面文件/交换文件");
            if (norm == "windows/memory.dmp") return new Rule("", "崩溃转储", "safe", "可删除", "完整内存转储");
            if (norm == "windows/panther/setupact.log" || norm == "windows/panther/setuperr.log") return new Rule("", "日志", "safe", "可删除", "系统升级日志");
            if (norm.IndexOf('/') < 0 && norm.EndsWith(".tmp") && size > 100L * 1024 * 1024) return new Rule("", "来源不明", "unknown", "先核实", "根目录下的大体积临时文件");
            if (norm.EndsWith(".dmp") && size > 100L * 1024 * 1024) return new Rule("", "崩溃转储", "safe", "可删除", "崩溃转储文件");
            return null;
        }
    }

    public class Scanner
    {
        private Dictionary<string, long> _dirSizes = new Dictionary<string, long>(StringComparer.Ordinal);
        private Dictionary<string, int> _dirCounts = new Dictionary<string, int>(StringComparer.Ordinal);
        private Dictionary<string, string> _dirIndex = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private List<FileRec> _large = new List<FileRec>();
        private Dictionary<string, long> _ext = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
        private List<DirRec> _top = new List<DirRec>();
        private long _files, _dirs, _bytes, _errors;
        private long _largeLimit;
        private long _seen;
        private string _rootNorm;
        private Action<ProgressInfo> _progress;
        private Func<bool> _cancel;
        private string _lastReportedDir = "";

        public ScanResult Scan(string rootInput, int largeFileMb, int depth, Action<ProgressInfo> progress, Func<bool> cancel)
        {
            string root = NormalizeRoot(rootInput);
            if (!Directory.Exists(root)) throw new DirectoryNotFoundException("扫描路径不存在：" + root);
            _progress = progress;
            _cancel = cancel;
            _largeLimit = Math.Max(0, largeFileMb) * 1024L * 1024L;
            _rootNorm = Normalize(root);
            string baseMatch = _rootNorm;
            if (baseMatch.Length >= 2 && baseMatch[1] == ':') baseMatch = baseMatch.Substring(2);
            baseMatch = baseMatch.Trim('/');

            DateTime started = DateTime.Now;
            Walk(root, "", baseMatch);
            double elapsed = (DateTime.Now - started).TotalSeconds;

            ScanResult result = new ScanResult();
            result.Root = root;
            result.ScannedAt = started;
            result.ElapsedSec = elapsed;
            result.Files = _files;
            result.Dirs = _dirs;
            result.Bytes = _bytes;
            result.Errors = _errors;
            result.Depth = depth;
            result.LargeFileMb = largeFileMb;
            result.Ext = _ext;
            try
            {
                DriveInfo di = new DriveInfo(root.Substring(0, 2));
                result.VolumeTotal = di.TotalSize;
                result.VolumeFree = di.TotalFreeSpace;
            }
            catch { }

            // candidates
            List<Candidate> dirCandidates = new List<Candidate>();
            foreach (KeyValuePair<string, long> kv in _dirSizes)
            {
                if (kv.Key.Length == 0 || kv.Value < 10L * 1024 * 1024) continue;
                string match = baseMatch.Length == 0 ? kv.Key : baseMatch + "/" + kv.Key;
                Rule rule = Rules.ClassifyDir(Normalize(match));
                if (rule == null) continue;
                Candidate c = new Candidate();
                c.Key = kv.Key;
                c.Path = Path.Combine(root, kv.Key);
                c.Bytes = kv.Value;
                c.Category = rule.Category;
                c.Risk = rule.Risk;
                c.Advice = rule.Advice;
                c.Note = rule.Note;
                dirCandidates.Add(c);
            }
            dirCandidates.Sort(delegate(Candidate a, Candidate b)
            {
                int l = a.Key.Length.CompareTo(b.Key.Length);
                if (l != 0) return l;
                return b.Bytes.CompareTo(a.Bytes);
            });
            List<Candidate> accepted = new List<Candidate>();
            foreach (Candidate c in dirCandidates)
            {
                string low = c.Key.ToLowerInvariant();
                bool covered = false;
                foreach (Candidate a in accepted)
                {
                    string p = a.Key.ToLowerInvariant();
                    if (low == p || low.StartsWith(p + "\\")) { covered = true; break; }
                }
                if (!covered) accepted.Add(c);
            }

            List<Candidate> fileCandidates = new List<Candidate>();
            foreach (FileRec f in _large)
            {
                string match = baseMatch.Length == 0 ? f.Key : baseMatch + "/" + f.Key;
                Rule rule = Rules.ClassifyFile(Normalize(match), f.Bytes);
                if (rule == null) continue;
                string low = f.Key.ToLowerInvariant();
                bool covered = false;
                foreach (Candidate a in accepted)
                {
                    string p = a.Key.ToLowerInvariant();
                    if (low == p || low.StartsWith(p + "\\")) { covered = true; break; }
                }
                if (covered) continue;
                Candidate c = new Candidate();
                c.Key = f.Key;
                c.Path = f.Path;
                c.Bytes = f.Bytes;
                c.Category = rule.Category;
                c.Risk = rule.Risk;
                c.Advice = rule.Advice;
                c.Note = rule.Note;
                fileCandidates.Add(c);
            }

            List<Candidate> all = new List<Candidate>();
            all.AddRange(accepted);
            all.AddRange(fileCandidates);
            all.Sort(delegate(Candidate a, Candidate b) { return b.Bytes.CompareTo(a.Bytes); });
            result.CandidateTotal = all.Count;
            result.Candidates = all.Take(300).ToList();

            // keep
            for (int i = 0; i < Rules.KeepDirs.GetLength(0); i++)
            {
                string rel = Rules.KeepDirs[i, 0].Replace('/', '\\');
                string original;
                if (_dirIndex.TryGetValue(rel, out original))
                {
                    Candidate k = new Candidate();
                    k.Key = original;
                    k.Path = Path.Combine(root, original);
                    k.Bytes = _dirSizes.ContainsKey(original) ? _dirSizes[original] : 0;
                    k.Note = Rules.KeepDirs[i, 1];
                    k.Category = "系统保留";
                    k.Risk = "keep";
                    k.Advice = "勿删";
                    result.Keep.Add(k);
                }
            }

            // top dirs
            foreach (DirRec d in _top) { }
            foreach (KeyValuePair<string, long> kv in _dirSizes)
            {
                if (kv.Key.Length == 0 || kv.Key.IndexOf('\\') >= 0) continue;
                DirRec d = new DirRec();
                d.Key = kv.Key;
                d.Bytes = kv.Value;
                d.Files = _dirCounts.ContainsKey(kv.Key) ? _dirCounts[kv.Key] : 0;
                result.TopDirs.Add(d);
            }
            result.TopDirs.Sort(delegate(DirRec a, DirRec b) { return b.Bytes.CompareTo(a.Bytes); });

            foreach (KeyValuePair<string, long> kv in _dirSizes)
            {
                if (kv.Key.Length == 0) continue;
                if (kv.Key.Split('\\').Length > depth) continue;
                DirRec d = new DirRec();
                d.Key = kv.Key;
                d.Bytes = kv.Value;
                d.Files = _dirCounts.ContainsKey(kv.Key) ? _dirCounts[kv.Key] : 0;
                result.DirsAtDepth.Add(d);
            }
            result.DirsAtDepth.Sort(delegate(DirRec a, DirRec b) { return b.Bytes.CompareTo(a.Bytes); });

            _large.Sort(delegate(FileRec a, FileRec b) { return b.Bytes.CompareTo(a.Bytes); });
            result.Large = _large.Take(200).ToList();
            return result;
        }

        private long Walk(string dirPath, string rel, string match)
        {
            if (_cancel != null && _cancel()) throw new OperationCanceledException();
            FileSystemInfo[] entries;
            try
            {
                entries = new DirectoryInfo(dirPath).GetFileSystemInfos();
            }
            catch
            {
                _errors++;
                return 0;
            }
            _dirs++;
            long bytes = 0;
            int count = 0;
            foreach (FileSystemInfo fsi in entries)
            {
                try
                {
                    FileAttributes attrs = fsi.Attributes;
                    if ((attrs & FileAttributes.ReparsePoint) != 0) continue;
                    string childRel = rel.Length == 0 ? fsi.Name : rel + "\\" + fsi.Name;
                    string childMatch = match.Length == 0 ? fsi.Name : match + "/" + fsi.Name;
                    if ((attrs & FileAttributes.Directory) != 0)
                    {
                        bytes += Walk(fsi.FullName, childRel, childMatch);
                        continue;
                    }
                    long size = 0;
                    FileInfo fi = fsi as FileInfo;
                    if (fi != null) size = fi.Length;
                    bytes += size;
                    count++;
                    _files++;
                    _bytes += size;
                    string lowName = fsi.Name.ToLowerInvariant();
                    int dot = lowName.LastIndexOf('.');
                    string ext = dot > 0 ? lowName.Substring(dot) : "(无扩展名)";
                    long prev;
                    _ext.TryGetValue(ext, out prev);
                    _ext[ext] = prev + size;
                    if (size >= _largeLimit)
                    {
                        FileRec fr = new FileRec();
                        fr.Path = fsi.FullName;
                        fr.Key = childRel;
                        fr.Bytes = size;
                        try { fr.MTime = fsi.LastWriteTime; } catch { fr.MTime = DateTime.MinValue; }
                        _large.Add(fr);
                    }
                }
                catch
                {
                    _errors++;
                }
            }
            _dirSizes[rel] = bytes;
            _dirCounts[rel] = count;
            _dirIndex[rel] = rel;
            _seen++;
            if (_progress != null && (_seen % 200 == 0 || bytes > 0))
            {
                ProgressInfo p = new ProgressInfo();
                p.Dirs = _dirs;
                p.Files = _files;
                p.Bytes = _bytes;
                p.CurrentDir = dirPath;
                _lastReportedDir = dirPath;
                try { _progress(p); } catch { }
            }
            return bytes;
        }

        public static string NormalizeRoot(string input)
        {
            string raw = (input ?? "C:").Trim();
            if (raw.Length == 0) raw = "C:";
            if (System.Text.RegularExpressions.Regex.IsMatch(raw, @"^[A-Za-z]:$")) raw = raw.ToUpperInvariant() + "\\";
            string full = Path.GetFullPath(raw);
            if (!full.EndsWith("\\")) full += "\\";
            return full;
        }

        public static string Normalize(string key)
        {
            return key.ToLowerInvariant().Replace('\\', '/');
        }
    }

    public static class Reports
    {
        public static readonly Dictionary<string, string> RiskLabel = new Dictionary<string, string>
        {
            { "safe", "A · 低风险" }, { "review", "B · 需确认" }, { "unknown", "C · 先核实" }, { "keep", "D · 勿删" }
        };

        private static string Gb(long bytes) { return (bytes / 1073741824.0).ToString("F2"); }
        private static string Gb3(long bytes) { return (bytes / 1073741824.0).ToString("F3"); }

        public static string FmtSize(long bytes)
        {
            double gb = bytes / 1073741824.0;
            if (gb >= 0.01) return gb.ToString("F2") + " GB";
            return (bytes / 1048576.0).ToString("F0") + " MB";
        }

        public static string SizeClass(long bytes)
        {
            double gb = bytes / 1073741824.0;
            if (gb >= 30) return "s5";
            if (gb >= 10) return "s4";
            if (gb >= 5) return "s3";
            if (gb >= 1) return "s2";
            if (gb >= 0.1) return "s1";
            return "s0";
        }

        public static string Esc(string s)
        {
            if (s == null) return "";
            return s.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;");
        }

        public static string JsonEsc(string s)
        {
            if (s == null) return "";
            StringBuilder sb = new StringBuilder();
            foreach (char ch in s)
            {
                switch (ch)
                {
                    case '\\': sb.Append("\\\\"); break;
                    case '"': sb.Append("\\\""); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        if (ch < 32) sb.Append("\\u").Append(((int)ch).ToString("x4"));
                        else sb.Append(ch);
                        break;
                }
            }
            return sb.ToString();
        }

        public static long SumRisk(ScanResult s, string risk)
        {
            long sum = 0;
            foreach (Candidate c in s.Candidates) if (c.Risk == risk) sum += c.Bytes;
            return sum;
        }

        public static int CountRisk(ScanResult s, string risk)
        {
            int n = 0;
            foreach (Candidate c in s.Candidates) if (c.Risk == risk) n++;
            return n;
        }

        public static string When(DateTime t) { return t.ToString("yyyy-MM-dd HH:mm:ss"); }

        public static string VolumeLine(ScanResult s)
        {
            if (s.VolumeTotal <= 0) return "未知";
            double total = s.VolumeTotal / 1073741824.0;
            double free = s.VolumeFree / 1073741824.0;
            return string.Format("{0:F1} GB，可用 {1:F2} GB（已用 {2:F2} GB）", total, free, total - free);
        }

        public static string BuildMarkdown(ScanResult s)
        {
            StringBuilder b = new StringBuilder();
            b.AppendLine("# " + s.Root + " 磁盘清理扫描报告");
            b.AppendLine();
            b.AppendLine("- 生成时间：" + When(s.ScannedAt));
            b.AppendLine("- 扫描路径：`" + s.Root + "`");
            b.AppendLine("- 耗时：" + s.ElapsedSec.ToString("F1") + " 秒，文件 " + s.Files.ToString("N0") + " 个，目录 " + s.Dirs.ToString("N0") + " 个，不可读 " + s.Errors + " 处");
            b.AppendLine("- 卷容量：" + VolumeLine(s));
            b.AppendLine("- 可枚举文件总量：**" + Gb(s.Bytes) + " GB**");
            b.AppendLine();
            b.AppendLine("> 本报告由只读扫描生成，未移动、删除或修改任何文件。");
            b.AppendLine();
            b.AppendLine("## 一、顶层目录占用");
            b.AppendLine();
            b.AppendLine("| 目录 | 占用 | 文件数 |");
            b.AppendLine("|---|---:|---:|");
            int n = 0;
            foreach (DirRec d in s.TopDirs)
            {
                if (n++ >= 15) break;
                b.AppendLine("| `" + d.Key + "` | **" + FmtSize(d.Bytes) + "** | " + d.Files.ToString("N0") + " |");
            }
            b.AppendLine();
            b.AppendLine("## 二、可清理候选（按占用从大到小）");
            b.AppendLine();
            int total = s.CandidateTotal;
            int shown = Math.Min(60, s.Candidates.Count);
            b.AppendLine("- 共发现 " + total + " 项候选，下表显示前 " + shown + " 项；A 级代表低风险，删除前仍需按「说明」操作。");
            b.AppendLine("- A 低风险：" + CountRisk(s, "safe") + " 项，合计 **" + Gb(SumRisk(s, "safe")) + " GB**");
            b.AppendLine("- B 需确认：" + CountRisk(s, "review") + " 项，合计 **" + Gb(SumRisk(s, "review")) + " GB**");
            b.AppendLine("- C 先核实：" + CountRisk(s, "unknown") + " 项，合计 **" + Gb(SumRisk(s, "unknown")) + " GB**");
            b.AppendLine();
            b.AppendLine("| # | 分级 | 类别 | 占用 | 路径 | 说明 |");
            b.AppendLine("|---:|---|---|---:|---|---|");
            for (int i = 0; i < shown; i++)
            {
                Candidate c = s.Candidates[i];
                b.AppendLine("| " + (i + 1) + " | " + RiskLabel[c.Risk] + " | " + c.Category + " | **" + FmtSize(c.Bytes) + "** | `" + c.Path + "` | " + c.Note + " |");
            }
            if (total > shown) b.AppendLine("\n> 仅显示前 " + shown + " 项，其余 " + (total - shown) + " 项见 disk-cleanup.csv / .json。");
            b.AppendLine();
            if (s.Large.Count > 0)
            {
                b.AppendLine("## 三、大文件（≥ " + s.LargeFileMb + " MB，前 30）");
                b.AppendLine();
                b.AppendLine("| # | 大小 | 最后修改 | 路径 |");
                b.AppendLine("|---:|---:|---|---|");
                for (int i = 0; i < Math.Min(30, s.Large.Count); i++)
                {
                    FileRec f = s.Large[i];
                    string mt = f.MTime == DateTime.MinValue ? "" : When(f.MTime);
                    b.AppendLine("| " + (i + 1) + " | " + FmtSize(f.Bytes) + " | " + mt + " | `" + f.Path + "` |");
                }
                b.AppendLine();
            }
            b.AppendLine("## 四、目录占用 TOP（深度 " + s.Depth + "，前 30）");
            b.AppendLine();
            b.AppendLine("| 目录 | 占用 | 文件数 |");
            b.AppendLine("|---|---:|---:|");
            for (int i = 0; i < Math.Min(30, s.DirsAtDepth.Count); i++)
            {
                DirRec d = s.DirsAtDepth[i];
                b.AppendLine("| `" + d.Key + "` | " + FmtSize(d.Bytes) + " | " + d.Files.ToString("N0") + " |");
            }
            b.AppendLine();
            b.AppendLine("## 五、不要手动删除");
            b.AppendLine();
            if (s.Keep.Count > 0)
            {
                foreach (Candidate k in s.Keep) b.AppendLine("- `" + k.Path + "`（" + FmtSize(k.Bytes) + "）— " + k.Note);
            }
            else b.AppendLine("- 本次扫描范围内未发现这些系统保留目录（扫描的是子目录时属正常）。");
            b.AppendLine();
            b.AppendLine("## 六、方法与限制");
            b.AppendLine();
            b.AppendLine("- 采用只读遍历，跳过符号链接/联接点，避免重复计数；无权限的目录计入「不可读」。");
            b.AppendLine("- 大小按文件逻辑长度累加；Windows 组件目录含硬链接，实际占用可能小于累加值。");
            b.AppendLine("- 未做病毒扫描、数字签名校验或文件内容分析；「来源不明」仅基于目录名与位置推断。");
            b.AppendLine("- 删除前请确认对应软件已退出；系统目录请使用系统自带清理工具（磁盘清理 / DISM）。");
            return b.ToString();
        }

        public static string BuildHtml(ScanResult s)
        {
            StringBuilder rows = new StringBuilder();
            int shown = Math.Min(200, s.Candidates.Count);
            for (int i = 0; i < shown; i++)
            {
                Candidate c = s.Candidates[i];
                rows.Append("<tr><td class=\"rank\">" + (i + 1) + "</td>");
                rows.Append("<td><span class=\"risk r-" + c.Risk + "\">" + Esc(RiskLabel[c.Risk]) + "</span></td>");
                rows.Append("<td>" + Esc(c.Category) + "</td>");
                rows.Append("<td class=\"size " + SizeClass(c.Bytes) + "\">" + FmtSize(c.Bytes) + "</td>");
                rows.Append("<td class=\"path\">" + Esc(c.Path) + "</td>");
                rows.Append("<td class=\"note\">" + Esc(c.Note) + "</td></tr>");
            }
            StringBuilder topRows = new StringBuilder();
            for (int i = 0; i < Math.Min(12, s.TopDirs.Count); i++)
            {
                DirRec d = s.TopDirs[i];
                topRows.Append("<tr><td class=\"path\">" + Esc(d.Key) + "</td><td class=\"size " + SizeClass(d.Bytes) + "\">" + FmtSize(d.Bytes) + "</td><td>" + d.Files.ToString("N0") + "</td></tr>");
            }
            StringBuilder largeRows = new StringBuilder();
            for (int i = 0; i < Math.Min(30, s.Large.Count); i++)
            {
                FileRec f = s.Large[i];
                string mt = f.MTime == DateTime.MinValue ? "" : When(f.MTime);
                largeRows.Append("<tr><td class=\"rank\">" + (i + 1) + "</td><td class=\"size " + SizeClass(f.Bytes) + "\">" + FmtSize(f.Bytes) + "</td><td>" + Esc(mt) + "</td><td class=\"path\">" + Esc(f.Path) + "</td></tr>");
            }
            StringBuilder keep = new StringBuilder();
            if (s.Keep.Count > 0)
            {
                foreach (Candidate k in s.Keep) keep.Append("<li><code>" + Esc(k.Path) + "</code>（" + FmtSize(k.Bytes) + "）— " + Esc(k.Note) + "</li>");
            }
            else keep.Append("<li>本次扫描范围内未发现这些系统保留目录（扫描子目录时属正常）。</li>");

            string css = @"
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body { margin: 0; padding: 28px 24px 60px; font: 14px/1.6 'Microsoft YaHei', 'Segoe UI', system-ui, sans-serif; color: #1f2937; background: #f5f7fb; }
  .wrap { max-width: 1180px; margin: 0 auto; }
  h1 { font-size: 24px; margin: 0 0 6px; color: #0f172a; }
  .meta { color: #64748b; font-size: 13px; margin-bottom: 20px; }
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-bottom: 22px; }
  .card { background: #fff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 14px 16px; }
  .card .k { color: #64748b; font-size: 12px; }
  .card .v { font-size: 22px; font-weight: 700; margin-top: 2px; }
  .card .v.red { color: #b91c1c; } .card .v.amber { color: #b45309; } .card .v.green { color: #15803d; }
  h2 { font-size: 17px; margin: 30px 0 10px; color: #0f172a; }
  table { width: 100%; border-collapse: collapse; background: #fff; border: 1px solid #e2e8f0; border-radius: 12px; overflow: hidden; }
  .tablewrap { overflow-x: auto; }
  th { background: #1f3864; color: #fff; text-align: left; font-weight: 600; padding: 10px 12px; font-size: 13px; white-space: nowrap; }
  td { padding: 9px 12px; border-top: 1px solid #eef2f7; vertical-align: middle; }
  tr:nth-child(even) td { background: #f8fafc; }
  .rank { color: #94a3b8; text-align: right; width: 46px; }
  .path { font-family: Consolas, 'Cascadia Mono', monospace; font-size: 12.5px; color: #334155; word-break: break-all; }
  .note { color: #64748b; font-size: 12.5px; }
  .size { font-family: Consolas, 'Cascadia Mono', monospace; font-weight: 700; text-align: right; white-space: nowrap; border-radius: 6px; }
  .size.s5 { background: #c00000; color: #fff; font-size: 16px; }
  .size.s4 { background: #e53935; color: #fff; font-size: 15px; }
  .size.s3 { background: #f4511e; color: #fff; }
  .size.s2 { background: #fde2c4; color: #c2410c; }
  .size.s1 { background: #fff2cc; color: #b45309; }
  .size.s0 { background: #f1f5f9; color: #64748b; font-weight: 600; }
  .risk { display: inline-block; padding: 1px 8px; border-radius: 999px; font-size: 12px; font-weight: 700; white-space: nowrap; }
  .r-safe { background: #e8f5e9; color: #1b5e20; }
  .r-review { background: #fff8e1; color: #b45309; }
  .r-unknown { background: #fdecea; color: #b71c1c; }
  .r-keep { background: #eceff1; color: #37474f; }
  ul { background: #fff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 14px 18px 14px 34px; margin: 0; }
  li { margin: 4px 0; }
  .foot { color: #94a3b8; font-size: 12px; margin-top: 26px; }
  code { background: #eef2f7; padding: 1px 5px; border-radius: 4px; }
  @media (max-width: 640px) { body { padding: 18px 12px 40px; } table { min-width: 640px; } .note { display: none; } .path { font-size: 11.5px; } }
  @media (prefers-color-scheme: dark) {
    body { background: #0f172a; color: #e2e8f0; }
    h1, h2 { color: #f1f5f9; }
    .card, table, ul { background: #111c31; border-color: #1e293b; }
    td { border-color: #1e293b; }
    tr:nth-child(even) td { background: #0e1929; }
    .path { color: #cbd5e1; }
    .note, .meta, .foot { color: #94a3b8; }
    code { background: #1e293b; }
    .size.s2 { background: #7c2d12; color: #ffedd5; }
    .size.s1 { background: #78350f; color: #fef3c7; }
    .size.s0 { background: #1e293b; color: #94a3b8; }
    .r-safe { background: #14532d; color: #bbf7d0; }
    .r-review { background: #78350f; color: #fde68a; }
    .r-unknown { background: #7f1d1d; color: #fecaca; }
  }";

            StringBuilder h = new StringBuilder();
            h.AppendLine("<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">");
            h.AppendLine("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">");
            h.AppendLine("<title>" + Esc(s.Root) + " 磁盘清理扫描报告</title><style>" + css + "</style></head><body><div class=\"wrap\">");
            h.AppendLine("<h1>" + Esc(s.Root) + " 磁盘清理扫描报告</h1>");
            h.AppendLine("<div class=\"meta\">生成时间 " + When(s.ScannedAt) + " · 耗时 " + s.ElapsedSec.ToString("F1") + " 秒 · 文件 " + s.Files.ToString("N0") + " 个 · 不可读 " + s.Errors + " 处 · 只读扫描，未改动任何文件</div>");
            h.AppendLine("<div class=\"cards\">");
            h.AppendLine("<div class=\"card\"><div class=\"k\">卷容量 / 可用</div><div class=\"v\">" + (s.VolumeTotal > 0 ? (s.VolumeTotal / 1073741824.0).ToString("F0") + " GB / " + (s.VolumeFree / 1073741824.0).ToString("F1") + " GB" : "未知") + "</div></div>");
            h.AppendLine("<div class=\"card\"><div class=\"k\">可枚举文件总量</div><div class=\"v\">" + Gb(s.Bytes) + " GB</div></div>");
            h.AppendLine("<div class=\"card\"><div class=\"k\">A 低风险（" + CountRisk(s, "safe") + " 项）</div><div class=\"v green\">" + Gb(SumRisk(s, "safe")) + " GB</div></div>");
            h.AppendLine("<div class=\"card\"><div class=\"k\">B 需确认（" + CountRisk(s, "review") + " 项）</div><div class=\"v amber\">" + Gb(SumRisk(s, "review")) + " GB</div></div>");
            h.AppendLine("<div class=\"card\"><div class=\"k\">C 先核实（" + CountRisk(s, "unknown") + " 项）</div><div class=\"v red\">" + Gb(SumRisk(s, "unknown")) + " GB</div></div>");
            h.AppendLine("</div>");
            h.AppendLine("<h2>可清理候选（按占用从大到小）</h2>");
            h.AppendLine("<div class=\"meta\">共 " + s.CandidateTotal + " 项，显示前 " + shown + " 项；A 级表示低风险，删除前仍请按「说明」操作。</div>");
            h.AppendLine("<div class=\"tablewrap\"><table><thead><tr><th>#</th><th>分级</th><th>类别</th><th style=\"text-align:right\">占用大小</th><th>路径</th><th>说明</th></tr></thead><tbody>" + rows + "</tbody></table></div>");
            h.AppendLine("<h2>顶层目录占用</h2><div class=\"tablewrap\"><table><thead><tr><th>目录</th><th style=\"text-align:right\">占用</th><th>文件数</th></tr></thead><tbody>" + topRows + "</tbody></table></div>");
            h.AppendLine("<h2>大文件（≥ " + s.LargeFileMb + " MB，前 30）</h2><div class=\"tablewrap\"><table><thead><tr><th>#</th><th style=\"text-align:right\">大小</th><th>最后修改</th><th>路径</th></tr></thead><tbody>" + largeRows + "</tbody></table></div>");
            h.AppendLine("<h2>不要手动删除</h2><ul>" + keep + "</ul>");
            h.AppendLine("<div class=\"foot\">只读遍历，跳过符号链接/联接点；大小按逻辑长度累加，Windows 组件目录含硬链接可能偏大。未做病毒扫描或数字签名校验。「来源不明」仅基于目录名与位置推断。</div>");
            h.AppendLine("</div></body></html>");
            return h.ToString();
        }

        public static string BuildCsv(ScanResult s)
        {
            StringBuilder b = new StringBuilder();
            b.Append("\uFEFF");
            b.AppendLine("\"序号\",\"分级\",\"类别\",\"路径\",\"大小GB\",\"建议\",\"说明\"");
            for (int i = 0; i < s.Candidates.Count; i++)
            {
                Candidate c = s.Candidates[i];
                b.AppendLine("\"" + (i + 1) + "\",\"" + RiskLabel[c.Risk] + "\",\"" + Q(c.Category) + "\",\"" + Q(c.Path) + "\",\"" + Gb(c.Bytes) + "\",\"" + Q(c.Advice) + "\",\"" + Q(c.Note) + "\"");
            }
            return b.ToString();
        }

        private static string Q(string v)
        {
            if (v == null) return "";
            return v.Replace("\"", "\"\"");
        }

        public static string BuildJson(ScanResult s)
        {
            StringBuilder b = new StringBuilder();
            b.Append("{\n  \"root\": \"" + JsonEsc(s.Root) + "\",\n");
            b.Append("  \"scannedAt\": \"" + s.ScannedAt.ToString("yyyy-MM-ddTHH:mm:ss") + "\",\n");
            b.Append("  \"elapsedSec\": " + s.ElapsedSec.ToString("F3") + ",\n");
            b.Append("  \"totals\": { \"files\": " + s.Files + ", \"dirs\": " + s.Dirs + ", \"bytes\": " + s.Bytes + ", \"errors\": " + s.Errors + " },\n");
            b.Append("  \"volume\": { \"totalBytes\": " + s.VolumeTotal + ", \"freeBytes\": " + s.VolumeFree + " },\n");
            b.Append("  \"candidateTotal\": " + s.CandidateTotal + ",\n");
            b.Append("  \"candidates\": [\n");
            for (int i = 0; i < s.Candidates.Count; i++)
            {
                Candidate c = s.Candidates[i];
                b.Append("    { \"path\": \"" + JsonEsc(c.Path) + "\", \"bytes\": " + c.Bytes + ", \"risk\": \"" + c.Risk + "\", \"category\": \"" + JsonEsc(c.Category) + "\", \"advice\": \"" + JsonEsc(c.Advice) + "\", \"note\": \"" + JsonEsc(c.Note) + "\" }");
                if (i < s.Candidates.Count - 1) b.Append(",");
                b.Append("\n");
            }
            b.Append("  ],\n  \"keep\": [\n");
            for (int i = 0; i < s.Keep.Count; i++)
            {
                Candidate k = s.Keep[i];
                b.Append("    { \"path\": \"" + JsonEsc(k.Path) + "\", \"bytes\": " + k.Bytes + ", \"note\": \"" + JsonEsc(k.Note) + "\" }");
                if (i < s.Keep.Count - 1) b.Append(",");
                b.Append("\n");
            }
            b.Append("  ]\n}\n");
            return b.ToString();
        }

        public static string[] WriteReports(ScanResult s, string outputDir)
        {
            Directory.CreateDirectory(outputDir);
            string basePath = Path.Combine(outputDir, "disk-cleanup");
            string md = basePath + ".md";
            string html = basePath + ".html";
            string csv = basePath + ".csv";
            string json = basePath + ".json";
            File.WriteAllText(md, BuildMarkdown(s), new UTF8Encoding(true));
            File.WriteAllText(html, BuildHtml(s), new UTF8Encoding(true));
            File.WriteAllText(csv, BuildCsv(s), new UTF8Encoding(true));
            File.WriteAllText(json, BuildJson(s), new UTF8Encoding(true));
            return new string[] { md, html, csv, json };
        }
    }

    public static class Cli
    {
        public static int Run(string[] args)
        {
            string path = "C:";
            string outDir = "";
            int threshold = 300;
            int depth = 2;
            for (int i = 1; i < args.Length; i++)
            {
                string a = args[i];
                if (a == "--path" && i + 1 < args.Length) path = args[++i];
                else if (a == "--out" && i + 1 < args.Length) outDir = args[++i];
                else if (a == "--threshold" && i + 1 < args.Length) int.TryParse(args[++i], out threshold);
                else if (a == "--depth" && i + 1 < args.Length) int.TryParse(args[++i], out depth);
            }
            depth = Math.Max(1, Math.Min(4, depth));
            Scanner scanner = new Scanner();
            ScanResult r = scanner.Scan(path, threshold, depth, null, null);
            if (outDir.Length == 0)
            {
                string tag = (r.Root.Length > 1 ? r.Root.Substring(0, 1) : "scan") + "-" + r.ScannedAt.ToString("yyyyMMdd-HHmmss");
                outDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "DSH-Scan", tag);
            }
            string[] files = Reports.WriteReports(r, outDir);
            StringBuilder b = new StringBuilder();
            b.AppendLine("root=" + r.Root);
            b.AppendLine("elapsed=" + r.ElapsedSec.ToString("F1"));
            b.AppendLine("files=" + r.Files);
            b.AppendLine("dirs=" + r.Dirs);
            b.AppendLine("bytesGB=" + (r.Bytes / 1073741824.0).ToString("F2"));
            b.AppendLine("errors=" + r.Errors);
            b.AppendLine("candidates=" + r.CandidateTotal);
            b.AppendLine("safeGB=" + (Reports.SumRisk(r, "safe") / 1073741824.0).ToString("F2"));
            b.AppendLine("reviewGB=" + (Reports.SumRisk(r, "review") / 1073741824.0).ToString("F2"));
            b.AppendLine("unknownGB=" + (Reports.SumRisk(r, "unknown") / 1073741824.0).ToString("F2"));
            b.AppendLine("html=" + files[1]);
            b.AppendLine("out=" + outDir);
            File.WriteAllText(Path.Combine(outDir, "summary.txt"), b.ToString(), new UTF8Encoding(true));
            return 0;
        }
    }

    public class MainForm : Form
    {
        private TextBox _txtPath;
        private NumericUpDown _numThreshold;
        private NumericUpDown _numDepth;
        private Button _btnScan;
        private Button _btnCancel;
        private Button _btnOpen;
        private Button _btnFolder;
        private ProgressBar _bar;
        private Label _lblStatus;
        private Label _lblSummary;
        private DataGridView _grid;
        private volatile bool _cancel;
        private ScanResult _result;
        private string _outDir;
        private string[] _files;
        private DateTime _startedAt;

        public MainForm()
        {
            Text = "磁盘清理扫描器 · 独立版";
            AutoScaleMode = AutoScaleMode.Font;
            AutoScaleDimensions = new SizeF(96F, 96F);
            ClientSize = new Size(1000, 660);
            MinimumSize = new Size(880, 560);
            StartPosition = FormStartPosition.CenterScreen;
            Font = new Font("Microsoft YaHei UI", 9f);
            BackColor = Color.FromArgb(245, 247, 251);

            Panel top = new Panel();
            top.Dock = DockStyle.Top;
            top.AutoSize = true;
            top.AutoSizeMode = AutoSizeMode.GrowAndShrink;
            top.BackColor = Color.White;
            top.Padding = new Padding(16, 12, 16, 10);
            Controls.Add(top);

            FlowLayoutPanel stack = new FlowLayoutPanel();
            stack.Dock = DockStyle.Top;
            stack.FlowDirection = FlowDirection.TopDown;
            stack.WrapContents = false;
            stack.AutoSize = true;
            stack.AutoSizeMode = AutoSizeMode.GrowAndShrink;
            stack.BackColor = Color.Transparent;
            top.Controls.Add(stack);

            Label title = new Label();
            title.Text = "磁盘清理扫描器";
            title.Font = new Font("Microsoft YaHei UI", 14f, FontStyle.Bold);
            title.ForeColor = Color.FromArgb(15, 23, 42);
            title.AutoSize = true;
            title.Margin = new Padding(2, 0, 0, 2);
            stack.Controls.Add(title);

            Label sub = new Label();
            sub.Text = "只读扫描，不删除、不移动任何文件；生成 MD / HTML / CSV / JSON 四种报告。";
            sub.ForeColor = Color.FromArgb(100, 116, 139);
            sub.AutoSize = true;
            sub.Margin = new Padding(3, 0, 0, 10);
            stack.Controls.Add(sub);

            FlowLayoutPanel row1 = new FlowLayoutPanel();
            row1.FlowDirection = FlowDirection.LeftToRight;
            row1.WrapContents = false;
            row1.AutoSize = true;
            row1.AutoSizeMode = AutoSizeMode.GrowAndShrink;
            row1.Margin = new Padding(0, 0, 0, 6);
            stack.Controls.Add(row1);

            Label lp = new Label();
            lp.Text = "扫描路径";
            lp.AutoSize = true;
            lp.Margin = new Padding(0, 8, 8, 0);
            row1.Controls.Add(lp);

            _txtPath = new TextBox();
            _txtPath.Text = "C:\\";
            _txtPath.Width = 320;
            _txtPath.Margin = new Padding(0, 4, 8, 0);
            row1.Controls.Add(_txtPath);

            Button btnBrowse = new Button();
            btnBrowse.Text = "浏览…";
            btnBrowse.AutoSize = true;
            btnBrowse.MinimumSize = new Size(70, 30);
            btnBrowse.Margin = new Padding(0, 2, 18, 0);
            btnBrowse.Click += delegate
            {
                FolderBrowserDialog d = new FolderBrowserDialog();
                d.Description = "选择要扫描的目录（C 盘通常选 C:\\）";
                if (d.ShowDialog(this) == DialogResult.OK) _txtPath.Text = d.SelectedPath;
            };
            row1.Controls.Add(btnBrowse);

            Label lt = new Label();
            lt.Text = "大文件阈值(MB)";
            lt.AutoSize = true;
            lt.Margin = new Padding(0, 8, 8, 0);
            row1.Controls.Add(lt);

            _numThreshold = new NumericUpDown();
            _numThreshold.Minimum = 0;
            _numThreshold.Maximum = 1000000;
            _numThreshold.Value = 300;
            _numThreshold.Increment = 100;
            _numThreshold.Width = 74;
            _numThreshold.Margin = new Padding(0, 4, 18, 0);
            row1.Controls.Add(_numThreshold);

            Label ld = new Label();
            ld.Text = "目录深度";
            ld.AutoSize = true;
            ld.Margin = new Padding(0, 8, 8, 0);
            row1.Controls.Add(ld);

            _numDepth = new NumericUpDown();
            _numDepth.Minimum = 1;
            _numDepth.Maximum = 4;
            _numDepth.Value = 2;
            _numDepth.Width = 46;
            _numDepth.Margin = new Padding(0, 4, 0, 0);
            row1.Controls.Add(_numDepth);

            FlowLayoutPanel row2 = new FlowLayoutPanel();
            row2.FlowDirection = FlowDirection.LeftToRight;
            row2.WrapContents = false;
            row2.AutoSize = true;
            row2.AutoSizeMode = AutoSizeMode.GrowAndShrink;
            row2.Margin = new Padding(0, 2, 0, 0);
            stack.Controls.Add(row2);

            _btnScan = new Button();
            _btnScan.Text = "开始扫描";
            _btnScan.Width = 110;
            _btnScan.Height = 32;
            _btnScan.BackColor = Color.FromArgb(31, 56, 100);
            _btnScan.ForeColor = Color.White;
            _btnScan.FlatStyle = FlatStyle.Flat;
            _btnScan.FlatAppearance.BorderSize = 0;
            _btnScan.Margin = new Padding(0, 0, 8, 0);
            _btnScan.Click += delegate { StartScan(); };
            row2.Controls.Add(_btnScan);

            _btnCancel = new Button();
            _btnCancel.Text = "取消";
            _btnCancel.Width = 76;
            _btnCancel.Height = 32;
            _btnCancel.Enabled = false;
            _btnCancel.Margin = new Padding(0, 0, 8, 0);
            _btnCancel.Click += delegate { _cancel = true; _lblStatus.Text = "正在取消…"; };
            row2.Controls.Add(_btnCancel);

            _btnOpen = new Button();
            _btnOpen.Text = "打开报告";
            _btnOpen.Width = 100;
            _btnOpen.Height = 32;
            _btnOpen.Enabled = false;
            _btnOpen.Margin = new Padding(0, 0, 8, 0);
            _btnOpen.Click += delegate { OpenHtml(); };
            row2.Controls.Add(_btnOpen);

            _btnFolder = new Button();
            _btnFolder.Text = "打开报告目录";
            _btnFolder.Width = 118;
            _btnFolder.Height = 32;
            _btnFolder.Enabled = false;
            _btnFolder.Margin = new Padding(0, 0, 14, 0);
            _btnFolder.Click += delegate { OpenFolder(); };
            row2.Controls.Add(_btnFolder);

            _bar = new ProgressBar();
            _bar.Style = ProgressBarStyle.Marquee;
            _bar.MarqueeAnimationSpeed = 0;
            _bar.Width = 220;
            _bar.Height = 18;
            _bar.Margin = new Padding(0, 8, 12, 0);
            row2.Controls.Add(_bar);

            Label lbar = new Label();
            lbar.Text = "扫描期间不要关闭程序";
            lbar.ForeColor = Color.FromArgb(148, 163, 184);
            lbar.AutoSize = true;
            lbar.Margin = new Padding(0, 10, 0, 0);
            row2.Controls.Add(lbar);

            Panel status = new Panel();
            status.Dock = DockStyle.Bottom;
            status.Height = 54;
            status.BackColor = Color.White;
            status.Padding = new Padding(16, 6, 16, 6);
            Controls.Add(status);

            _lblStatus = new Label();
            _lblStatus.Text = "就绪：选择路径后点「开始扫描」。";
            _lblStatus.AutoSize = true;
            _lblStatus.Location = new Point(16, 6);
            status.Controls.Add(_lblStatus);

            _lblSummary = new Label();
            _lblSummary.Text = "";
            _lblSummary.AutoSize = true;
            _lblSummary.ForeColor = Color.FromArgb(71, 85, 105);
            _lblSummary.Location = new Point(16, 28);
            status.Controls.Add(_lblSummary);

            _grid = new DataGridView();
            _grid.Dock = DockStyle.Fill;
            _grid.AllowUserToAddRows = false;
            _grid.AllowUserToDeleteRows = false;
            _grid.ReadOnly = true;
            _grid.RowHeadersVisible = false;
            _grid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
            _grid.MultiSelect = false;
            _grid.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.None;
            _grid.BackgroundColor = Color.White;
            _grid.BorderStyle = BorderStyle.None;
            _grid.CellDoubleClick += delegate(object sender, DataGridViewCellEventArgs e)
            {
                if (e.RowIndex >= 0 && _result != null && e.RowIndex < _result.Candidates.Count)
                {
                    string p = _result.Candidates[e.RowIndex].Path;
                    try { Process.Start("explorer.exe", "/select,\"" + p + "\""); } catch { }
                }
            };
            DataGridViewTextBoxColumn c1 = new DataGridViewTextBoxColumn(); c1.HeaderText = "#"; c1.Width = 44; c1.ReadOnly = true;
            DataGridViewTextBoxColumn c2 = new DataGridViewTextBoxColumn(); c2.HeaderText = "分级"; c2.Width = 96;
            DataGridViewTextBoxColumn c3 = new DataGridViewTextBoxColumn(); c3.HeaderText = "类别"; c3.Width = 92;
            DataGridViewTextBoxColumn c4 = new DataGridViewTextBoxColumn(); c4.HeaderText = "占用"; c4.Width = 96; c4.DefaultCellStyle.Alignment = DataGridViewContentAlignment.MiddleRight;
            DataGridViewTextBoxColumn c5 = new DataGridViewTextBoxColumn(); c5.HeaderText = "路径"; c5.Width = 420;
            DataGridViewTextBoxColumn c6 = new DataGridViewTextBoxColumn(); c6.HeaderText = "说明"; c6.AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill;
            _grid.Columns.Add(c1); _grid.Columns.Add(c2); _grid.Columns.Add(c3); _grid.Columns.Add(c4); _grid.Columns.Add(c5); _grid.Columns.Add(c6);
            Controls.Add(_grid);
            Controls.SetChildIndex(_grid, 0);
            Controls.SetChildIndex(top, 1);
            Controls.SetChildIndex(status, 2);
        }

        protected override void OnLoad(EventArgs e)
        {
            base.OnLoad(e);
            Rectangle wa = Screen.FromControl(this).WorkingArea;
            int w = Math.Min(Width, wa.Width - 24);
            int h = Math.Min(Height, wa.Height - 24);
            if (w != Width || h != Height) { Width = w; Height = h; }

            if (Right > wa.Right) Left = wa.Right - Width;
            if (Bottom > wa.Bottom) Top = wa.Bottom - Height;
            if (Left < wa.Left) Left = wa.Left;
            if (Top < wa.Top) Top = wa.Top;
        }

        private void StartScan()
        {
            string path = _txtPath.Text.Trim();
            if (path.Length == 0) { MessageBox.Show(this, "请填写扫描路径。", "磁盘清理扫描器"); return; }
            try { path = Scanner.NormalizeRoot(path); } catch (Exception ex) { MessageBox.Show(this, ex.Message, "路径无效"); return; }
            if (!Directory.Exists(path)) { MessageBox.Show(this, "路径不存在：" + path, "磁盘清理扫描器"); return; }

            _cancel = false;
            _result = null;
            _files = null;
            _grid.Rows.Clear();
            _btnScan.Enabled = false;
            _btnCancel.Enabled = true;
            _btnOpen.Enabled = false;
            _btnFolder.Enabled = false;
            _bar.MarqueeAnimationSpeed = 30;
            _startedAt = DateTime.Now;
            _lblStatus.Text = "正在扫描 " + path + " …";
            _lblSummary.Text = "";

            int threshold = (int)_numThreshold.Value;
            int depth = (int)_numDepth.Value;
            Thread t = new Thread(delegate()
            {
                try
                {
                    Scanner scanner = new Scanner();
                    ScanResult r = scanner.Scan(path, threshold, depth, delegate(ProgressInfo p)
                    {
                        try
                        {
                            BeginInvoke((Action)delegate
                            {
                                double sec = (DateTime.Now - _startedAt).TotalSeconds;
                                _lblStatus.Text = string.Format("已扫描 {0:N0} 个文件 · {1:F0} 秒 · {2}", p.Files, sec, Shorten(p.CurrentDir, 70));
                            });
                        }
                        catch { }
                    }, delegate() { return _cancel; });

                    string tag = (r.Root.Length > 1 ? r.Root.Substring(0, 1) : "scan") + "-" + r.ScannedAt.ToString("yyyyMMdd-HHmmss");
                    string outDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "DSH-Scan", tag);
                    string[] files = Reports.WriteReports(r, outDir);

                    BeginInvoke((Action)delegate { FinishScan(r, outDir, files); });
                }
                catch (OperationCanceledException)
                {
                    BeginInvoke((Action)delegate
                    {
                        _btnScan.Enabled = true; _btnCancel.Enabled = false; _bar.MarqueeAnimationSpeed = 0;
                        _lblStatus.Text = "扫描已取消。";
                    });
                }
                catch (Exception ex)
                {
                    BeginInvoke((Action)delegate
                    {
                        _btnScan.Enabled = true; _btnCancel.Enabled = false; _bar.MarqueeAnimationSpeed = 0;
                        _lblStatus.Text = "扫描失败：" + ex.Message;
                        MessageBox.Show(this, ex.ToString(), "扫描失败");
                    });
                }
            });
            t.IsBackground = true;
            t.Start();
        }

        private void FinishScan(ScanResult r, string outDir, string[] files)
        {
            _result = r;
            _outDir = outDir;
            _files = files;
            _btnScan.Enabled = true;
            _btnCancel.Enabled = false;
            _bar.MarqueeAnimationSpeed = 0;
            _btnOpen.Enabled = true;
            _btnFolder.Enabled = true;

            _grid.SuspendLayout();
            for (int i = 0; i < r.Candidates.Count; i++)
            {
                Candidate c = r.Candidates[i];
                int idx = _grid.Rows.Add();
                DataGridViewRow row = _grid.Rows[idx];
                row.Cells[0].Value = (i + 1).ToString();
                row.Cells[1].Value = Reports.RiskLabel[c.Risk];
                row.Cells[2].Value = c.Category;
                row.Cells[3].Value = Reports.FmtSize(c.Bytes);
                row.Cells[4].Value = c.Path;
                row.Cells[5].Value = c.Note;
                Color back = Color.White;
                if (c.Risk == "safe") back = Color.FromArgb(240, 249, 240);
                else if (c.Risk == "review") back = Color.FromArgb(255, 250, 235);
                else if (c.Risk == "unknown") back = Color.FromArgb(253, 240, 238);
                row.DefaultCellStyle.BackColor = back;
                long gb = c.Bytes;
                if (gb >= 5L * 1024 * 1024 * 1024) row.Cells[3].Style.ForeColor = Color.FromArgb(185, 28, 28);
                else if (gb >= 1024L * 1024 * 1024) row.Cells[3].Style.ForeColor = Color.FromArgb(194, 65, 12);
            }
            _grid.ResumeLayout();


            _lblStatus.Text = string.Format("完成：{0:N0} 个文件 · {1:F1} 秒 · 报告已保存到 {2}", r.Files, r.ElapsedSec, outDir);
            _lblSummary.Text = string.Format("A 低风险 {0} 项 {1} GB　|　B 需确认 {2} 项 {3} GB　|　C 先核实 {4} 项 {5} GB　|　候选共 {6} 项",
                Reports.CountRisk(r, "safe"), (Reports.SumRisk(r, "safe") / 1073741824.0).ToString("F2"),
                Reports.CountRisk(r, "review"), (Reports.SumRisk(r, "review") / 1073741824.0).ToString("F2"),
                Reports.CountRisk(r, "unknown"), (Reports.SumRisk(r, "unknown") / 1073741824.0).ToString("F2"),
                r.CandidateTotal);
        }

        private static string Shorten(string s, int max)
        {
            if (s == null) return "";
            if (s.Length <= max) return s;
            return "…" + s.Substring(s.Length - max + 1);
        }

        private void OpenHtml()
        {
            if (_files == null || _files.Length < 2) return;
            string html = _files[1];
            if (!File.Exists(html)) { MessageBox.Show(this, "报告文件不存在：" + html); return; }
            string[] browsers = new string[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Microsoft\\Edge\\Application\\msedge.exe"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Microsoft\\Edge\\Application\\msedge.exe"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Google\\Chrome\\Application\\chrome.exe"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Google\\Chrome\\Application\\chrome.exe")
            };
            foreach (string b in browsers)
            {
                if (File.Exists(b))
                {
                    try
                    {
                        Process.Start(new ProcessStartInfo(b, "--new-window \"" + html + "\"") { UseShellExecute = false });
                        return;
                    }
                    catch { }
                }
            }
            try { Process.Start(new ProcessStartInfo(html) { UseShellExecute = true }); }
            catch (Exception ex) { MessageBox.Show(this, ex.Message); }
        }

        private void OpenFolder()
        {
            if (_files == null || _files.Length < 2) return;
            try { Process.Start("explorer.exe", "/select,\"" + _files[1] + "\""); }
            catch { }
        }
    }
}
