import fs from 'node:fs'
import path from 'node:path'

export const GB = 1024 ** 3
export const MB = 1024 ** 2

export function normalizeRoot(input) {
  const raw = (input || 'C:').trim()
  if (/^[A-Za-z]:$/.test(raw)) return raw.toUpperCase() + '\\'
  return path.resolve(raw)
}

export function driveTag(root) {
  const m = /^([A-Za-z]):/.exec(root)
  return m ? m[1].toUpperCase() : 'scan'
}

export function stamp(date = new Date()) {
  const p = (n) => String(n).padStart(2, '0')
  return `${date.getFullYear()}${p(date.getMonth() + 1)}${p(date.getDate())}-${p(date.getHours())}${p(date.getMinutes())}${p(date.getSeconds())}`
}

function norm(key) {
  return key.toLowerCase().replace(/\\/g, '/')
}

function matchKey(key, base) {
  if (!key) return base
  const n = norm(key)
  return base ? base + '/' + n : n
}

// ---------------------------------------------------------------- rules

const DIR_RULES = [
  // Windows servicing / logs
  { re: /^windows\/softwaredistribution\/download$/, cat: '更新缓存', risk: 'safe', advice: '可删除', note: 'Windows 更新下载缓存，删前先停止 wuauserv 服务' },
  { re: /^windows\/softwaredistribution\/deliveryoptimization$/, cat: '更新缓存', risk: 'safe', advice: '可删除', note: '传递优化缓存' },
  { re: /^windows\/logs$/, cat: '日志', risk: 'safe', advice: '可删除', note: '系统日志' },
  { re: /^windows\/panther$/, cat: '日志', risk: 'safe', advice: '可删除', note: '系统升级日志（setupact.log 等）' },
  { re: /^windows\/winsxs\/temp$/, cat: '系统缓存', risk: 'safe', advice: '建议用磁盘清理', note: '组件存储临时文件' },
  { re: /^windows\/servicing\/sessions$/, cat: '系统缓存', risk: 'safe', advice: '建议用磁盘清理', note: '更新会话数据' },
  { re: /^windows\/temp$/, cat: '临时文件', risk: 'safe', advice: '可删除', note: '系统临时目录' },
  { re: /^windows\/prefetch$/, cat: '系统缓存', risk: 'safe', advice: '可删除', note: '预读取缓存，自动重建' },
  { re: /^windows\/minidump$/, cat: '崩溃转储', risk: 'safe', advice: '可删除', note: '蓝屏小型转储' },
  { re: /^windows\/livekernelreports$/, cat: '崩溃转储', risk: 'safe', advice: '可删除', note: '内核实时报告' },
  // ProgramData caches
  { re: /^programdata\/nvidia corporation\/(downloader|nv_cache)$/, cat: '显卡缓存', risk: 'safe', advice: '可删除', note: 'NVIDIA 驱动下载/着色器缓存' },
  { re: /^programdata\/microsoft\/windows\/(wer|deliveryoptimization)$/, cat: '系统缓存', risk: 'safe', advice: '可删除', note: '错误报告/传递优化缓存' },
  { re: /^programdata\/lenovo\/leappstore\/cicada$/, cat: '软件缓存', risk: 'safe', advice: '可删除', note: '联想应用商店下载缓存（哈希命名安装包）' },
  // User temp / crash / thumbnails
  { re: /^users\/[^/]+\/appdata\/local\/temp$/, cat: '临时文件', risk: 'safe', advice: '可删除', note: '用户临时目录' },
  { re: /^users\/[^/]+\/appdata\/local\/crashdumps$/, cat: '崩溃转储', risk: 'safe', advice: '可删除', note: '应用崩溃转储' },
  { re: /^users\/[^/]+\/appdata\/local\/microsoft\/windows\/(explorer|inetcache|webcache)$/, cat: '缓存', risk: 'safe', advice: '可删除', note: '缩略图/IE/系统缓存' },
  { re: /^users\/[^/]+\/appdata\/local\/nvidia\/(dxcache|glcache)$/, cat: '显卡缓存', risk: 'safe', advice: '可删除', note: '着色器缓存，进游戏自动重建' },
  { re: /^users\/[^/]+\/appdata\/locallow\/nvidia$/, cat: '显卡缓存', risk: 'safe', advice: '可删除', note: '按驱动版本分的着色器缓存' },
  { re: /^users\/[^/]+\/appdata\/local\/d3dscache$/, cat: '显卡缓存', risk: 'safe', advice: '可删除', note: 'DirectX 着色器缓存' },
  { re: /^users\/[^/]+\/appdata\/local\/jetbrains$/, cat: 'IDE 缓存', risk: 'safe', advice: '可删除', note: 'JetBrains 索引缓存，可在 IDE 内清理' },
  { re: /^users\/[^/]+\/appdata\/local\/google\/androidstudio[^/]*$/, cat: 'IDE 缓存', risk: 'safe', advice: '可删除', note: 'Android Studio 索引缓存' },
  { re: /^users\/[^/]+\/appdata\/local\/steam\/htmlcache$/, cat: '缓存', risk: 'safe', advice: '可删除', note: 'Steam 网页缓存' },
  { re: /^users\/[^/]+\/appdata\/local\/[^/]+-updater$/, cat: '安装包残留', risk: 'safe', advice: '可删除', note: '软件更新器下载的安装包' },
  // Browser caches
  { re: /^users\/[^/]+\/appdata\/local\/(microsoft\/edge|google\/chrome)\/user data\/[^/]+\/(cache|code cache|gpucache|shadercache)$/, cat: '浏览器缓存', risk: 'safe', advice: '可删除', note: '浏览器缓存，勿删整个浏览器数据目录' },
  // Personal data
  { re: /^users\/[^/]+\/documents\/wechat files$/, cat: '个人数据', risk: 'review', advice: '需确认', note: '微信聊天文件，建议在微信内清理' },
  { re: /^users\/[^/]+\/documents\/tencent files$/, cat: '个人数据', risk: 'review', advice: '需确认', note: 'QQ 接收文件，建议在 QQ 内清理' },
  { re: /^users\/[^/]+\/appdata\/aclos$/, cat: '游戏录像', risk: 'review', advice: '需确认', note: '游戏自动录制的高光片段（mp4）' },
  { re: /^users\/[^/]+\/appdata\/roaming\/(kingsoft|wps)$/, cat: '软件缓存', risk: 'review', advice: '需确认', note: 'WPS 缓存/备份/插件' },
  { re: /^users\/[^/]+\/downloads$/, cat: '下载目录', risk: 'review', advice: '需确认', note: '下载文件，含旧安装包与个人文件' },
  { re: /^users\/[^/]+\/appdata\/local\/packages$/, cat: '应用缓存', risk: 'review', advice: '逐个清理', note: 'UWP 应用缓存，建议在 设置-应用 中清理' },
  // Unknown leftovers
  { re: /^programdata\/webhelper[^/]*$/, cat: '来源不明', risk: 'unknown', advice: '先核实', note: '疑似捆绑安装器残留（CEF 内核）' },
  { re: /^programdata\/sakurafrp[^/]*$/, cat: '来源不明', risk: 'unknown', advice: '先核实', note: '内网穿透工具，不用建议卸载' },
  { re: /^programdata\/qiyi$/, cat: '软件残留', risk: 'review', advice: '可删除', note: '爱奇艺 P2P 组件残留' },
  { re: /^users\/[^/]+\/appdata\/roaming\/iqiyi video$/, cat: '软件残留', risk: 'review', advice: '可删除', note: '爱奇艺残留缓存' },
  { re: /^programdata\/(xfolder|tianxiang|whesvc|dbg)$/, cat: '来源不明', risk: 'unknown', advice: '先核实', note: '来源不明的小型残留目录' }
]

const GENERIC_CACHE = /\/cache$|\/code cache$|\/gpucache$|\/shadercache$|\/cache_data$/
const GENERIC_LOG = /\/logs?$/

const KEEP_DIRS = [
  { key: 'windows/winsxs', note: '组件存储，只能用 DISM /StartComponentCleanup 清理' },
  { key: 'windows/installer', note: 'MSI 缓存，删除会导致软件无法卸载/修复' },
  { key: 'windows/system32/driverstore', note: '驱动仓库，删除会导致驱动失效' },
  { key: 'programdata/package cache', note: '安装包缓存，卸载/修复软件时需要' },
  { key: 'windows/assembly', note: '.NET 程序集缓存' },
  { key: 'system volume information', note: '系统还原点，需管理员权限处理' }
]

function classifyDir(key) {
  const n = norm(key)
  for (const rule of DIR_RULES) {
    if (rule.re.test(n)) return rule
  }
  if ((n.startsWith('users/') && n.includes('/appdata/')) || n.startsWith('programdata/')) {
    if (GENERIC_CACHE.test(n)) return { cat: '通用缓存', risk: 'safe', advice: '可删除', note: '应用缓存目录（通用规则匹配）' }
    if (GENERIC_LOG.test(n)) return { cat: '日志', risk: 'safe', advice: '可删除', note: '应用日志目录（通用规则匹配）' }
  }
  return null
}

function classifyFile(key, size) {
  const n = norm(key)
  const base = n.split('/').pop()
  if (n === 'hiberfil.sys') return { cat: '休眠文件', risk: 'review', advice: '可选', note: '管理员执行 powercfg /h off 可释放，会失去休眠/快速启动' }
  if (base === 'pagefile.sys' || base === 'swapfile.sys') return { cat: '系统文件', risk: 'keep', advice: '勿删', note: '页面文件/交换文件' }
  if (n === 'windows/memory.dmp') return { cat: '崩溃转储', risk: 'safe', advice: '可删除', note: '完整内存转储' }
  if (n === 'windows/panther/setupact.log' || n === 'windows/panther/setuperr.log') return { cat: '日志', risk: 'safe', advice: '可删除', note: '系统升级日志' }
  if (!n.includes('/') && n.endsWith('.tmp') && size > 100 * MB) return { cat: '来源不明', risk: 'unknown', advice: '先核实', note: '根目录下的大体积临时文件' }
  if (n.endsWith('.dmp') && size > 100 * MB) return { cat: '崩溃转储', risk: 'safe', advice: '可删除', note: '崩溃转储文件' }
  return null
}

// ---------------------------------------------------------------- scan

export function scanTree(options = {}) {
  const startedAt = Date.now()
  const root = normalizeRoot(options.root)
  if (!fs.existsSync(root)) throw new Error(`扫描路径不存在: ${root}`)

  const lfRaw = Number(options.largeFileMb ?? 300)
  const largeLimit = Math.max(0, Number.isFinite(lfRaw) ? lfRaw : 300) * MB
  const dirSizes = new Map() // original-case relative key -> bytes
  const dirCounts = new Map()
  const dirIndex = new Map() // lowercase key -> original key
  const large = []
  const extBytes = new Map()
  const totals = { files: 0, dirs: 0, bytes: 0, errors: 0 }

  const baseMatch = norm(root).replace(/^[a-z]:\//, '').replace(/\/+$/, '')

  const walk = (dir, key, match) => {
    let entries
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true })
    } catch {
      totals.errors++
      return { bytes: 0, count: 0 }
    }
    totals.dirs++
    let bytes = 0
    let count = 0
    for (const ent of entries) {
      const full = path.join(dir, ent.name)
      const childKey = key ? key + '\\' + ent.name : ent.name
      const childMatch = match ? match + '/' + ent.name : ent.name
      let st
      try {
        st = fs.lstatSync(full)
      } catch {
        totals.errors++
        continue
      }
      if (st.isSymbolicLink()) continue
      if (st.isDirectory()) {
        const sub = walk(full, childKey, childMatch)
        bytes += sub.bytes
        count += sub.count
        continue
      }
      if (!st.isFile()) continue
      bytes += st.size
      count++
      totals.files++
      totals.bytes += st.size
      const low = childKey.toLowerCase()
      const dot = low.lastIndexOf('.')
      const ext = dot > 0 ? low.slice(dot) : '(无扩展名)'
      extBytes.set(ext, (extBytes.get(ext) || 0) + st.size)
      if (st.size >= largeLimit) {
        large.push({ path: full, key: childKey, bytes: st.size, mtime: st.mtime.toISOString() })
      }
    }
    dirSizes.set(key, bytes)
    dirCounts.set(key, count)
    dirIndex.set(key.toLowerCase(), key)
    return { bytes, count }
  }

  walk(root, '', baseMatch)

  let volume = null
  try {
    const st = fs.statfsSync(root)
    volume = { totalBytes: Number(st.bsize) * Number(st.blocks), freeBytes: Number(st.bsize) * Number(st.bavail) }
  } catch { /* ignore */ }

  // directory candidates
  const dirCandidates = []
  for (const [key, size] of dirSizes) {
    if (!key || size < 10 * MB) continue
    const rule = classifyDir(matchKey(key, baseMatch))
    if (!rule) continue
    dirCandidates.push({
      key,
      path: path.join(root, key),
      bytes: size,
      category: rule.cat,
      risk: rule.risk,
      advice: rule.advice,
      note: rule.note
    })
  }

  // keep only the shallowest matching ancestor for nested matches
  dirCandidates.sort((a, b) => a.key.length - b.key.length || b.bytes - a.bytes)
  const accepted = []
  for (const c of dirCandidates) {
    const low = c.key.toLowerCase()
    const covered = accepted.some((a) => {
      const p = a.key.toLowerCase()
      return low === p || low.startsWith(p + '\\')
    })
    if (!covered) accepted.push(c)
  }

  // file candidates not already covered by an accepted directory
  const fileCandidates = []
  for (const f of large) {
    const rule = classifyFile(matchKey(f.key, baseMatch), f.bytes)
    if (!rule) continue
    const low = f.key.toLowerCase()
    const covered = accepted.some((a) => {
      const p = a.key.toLowerCase()
      return low === p || low.startsWith(p + '\\')
    })
    if (covered) continue
    fileCandidates.push({
      key: f.key,
      path: f.path,
      bytes: f.bytes,
      category: rule.cat,
      risk: rule.risk,
      advice: rule.advice,
      note: rule.note
    })
  }

  const candidates = [...accepted, ...fileCandidates].sort((a, b) => b.bytes - a.bytes)
  const candidateTotal = candidates.length

  const keep = []
  for (const k of KEEP_DIRS) {
    const rel = k.key.replace(/\//g, '\\')
    const original = dirIndex.get(rel.toLowerCase())
    if (!original) continue
    keep.push({ key: original, path: path.join(root, original), bytes: dirSizes.get(original) ?? 0, note: k.note })
  }

  const topDirs = []
  for (const [key, size] of dirSizes) {
    if (!key || key.includes('\\')) continue
    topDirs.push({ name: key, bytes: size, files: dirCounts.get(key) || 0 })
  }
  topDirs.sort((a, b) => b.bytes - a.bytes)

  const depth = Math.min(4, Math.max(1, Number(options.depth ?? 2) || 2))
  const dirsAtDepth = []
  for (const [key, size] of dirSizes) {
    if (!key) continue
    if (key.split('\\').length > depth) continue
    dirsAtDepth.push({ key, bytes: size, files: dirCounts.get(key) || 0 })
  }
  dirsAtDepth.sort((a, b) => b.bytes - a.bytes)

  const extensions = [...extBytes.entries()]
    .map(([ext, bytes]) => ({ ext, bytes }))
    .sort((a, b) => b.bytes - a.bytes)
    .slice(0, 15)

  large.sort((a, b) => b.bytes - a.bytes)

  return {
    root,
    scannedAt: new Date().toISOString(),
    elapsedSec: (Date.now() - startedAt) / 1000,
    totals,
    volume,
    topDirs,
    dirsAtDepth,
    large: large.slice(0, 200),
    candidates: candidates.slice(0, 300),
    candidateTotal,
    keep,
    extensions,
    options: { depth, largeFileMb: largeLimit / MB }
  }
}

export function summarize(scan, outputs) {
  const sum = (risk) => scan.candidates.filter((c) => c.risk === risk).reduce((a, c) => a + c.bytes, 0) / GB
  const cnt = (risk) => scan.candidates.filter((c) => c.risk === risk).length
  return {
    root: scan.root,
    scannedAt: scan.scannedAt,
    elapsedSec: Math.round(scan.elapsedSec * 10) / 10,
    totalGB: Math.round((scan.totals.bytes / GB) * 100) / 100,
    freeGB: scan.volume ? Math.round((scan.volume.freeBytes / GB) * 100) / 100 : null,
    volumeGB: scan.volume ? Math.round((scan.volume.totalBytes / GB) * 100) / 100 : null,
    files: scan.totals.files,
    dirs: scan.totals.dirs,
    errors: scan.totals.errors,
    candidateCount: scan.candidateTotal ?? scan.candidates.length,
    safeGB: Math.round(sum('safe') * 100) / 100,
    reviewGB: Math.round(sum('review') * 100) / 100,
    unknownGB: Math.round(sum('unknown') * 100) / 100,
    safeCount: cnt('safe'),
    reviewCount: cnt('review'),
    unknownCount: cnt('unknown'),
    topDirs: scan.topDirs.slice(0, 8).map((d) => ({ name: d.name, gb: Math.round((d.bytes / GB) * 100) / 100 })),
    topCandidates: scan.candidates.slice(0, 8).map((c) => ({
      path: c.path,
      gb: Math.round((c.bytes / GB) * 100) / 100,
      risk: c.risk,
      category: c.category
    })),
    outputs
  }
}



