import fs from 'node:fs'
import path from 'node:path'
import { GB, MB } from './scan.js'

const RISK_LABEL = { safe: 'A · 低风险', review: 'B · 需确认', unknown: 'C · 先核实', keep: 'D · 勿删' }

export function fmtGB(bytes) {
  const gb = bytes / GB
  if (gb >= 0.01) return gb.toFixed(2) + ' GB'
  return (bytes / MB).toFixed(0) + ' MB'
}

function sizeClass(bytes) {
  const gb = bytes / GB
  if (gb >= 30) return 's5'
  if (gb >= 10) return 's4'
  if (gb >= 5) return 's3'
  if (gb >= 1) return 's2'
  if (gb >= 0.1) return 's1'
  return 's0'
}

function esc(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}

function when(iso) {
  try { return new Date(iso).toLocaleString('zh-CN', { hour12: false }) } catch { return iso }
}

function volumeLine(scan) {
  if (!scan.volume) return '未知'
  const total = scan.volume.totalBytes / GB
  const free = scan.volume.freeBytes / GB
  return `${total.toFixed(1)} GB，可用 ${free.toFixed(2)} GB（已用 ${(total - free).toFixed(2)} GB）`
}

export function buildMarkdown(scan) {
  const lines = []
  const p = (s = '') => lines.push(s)
  p(`# ${scan.root} 磁盘清理扫描报告`)
  p()
  p(`- 生成时间：${when(scan.scannedAt)}`)
  p(`- 扫描路径：\`${scan.root}\``)
  p(`- 耗时：${scan.elapsedSec.toFixed(1)} 秒，文件 ${scan.totals.files.toLocaleString('en-US')} 个，目录 ${scan.totals.dirs.toLocaleString('en-US')} 个，不可读 ${scan.totals.errors} 处`)
  p(`- 卷容量：${volumeLine(scan)}`)
  p(`- 可枚举文件总量：**${(scan.totals.bytes / GB).toFixed(2)} GB**`)
  p()
  p('> 本报告由只读扫描生成，未移动、删除或修改任何文件。')
  p()
  p('## 一、顶层目录占用')
  p()
  p('| 目录 | 占用 | 文件数 |')
  p('|---|---:|---:|')
  for (const d of scan.topDirs.slice(0, 15)) {
    p(`| \`${d.name}\` | **${fmtGB(d.bytes)}** | ${d.files.toLocaleString('en-US')} |`)
  }
  p()
  p('## 二、可清理候选（按占用从大到小）')
  p()
  const sum = (risk) => scan.candidates.filter((c) => c.risk === risk).reduce((a, c) => a + c.bytes, 0) / GB
  const cnt = (risk) => scan.candidates.filter((c) => c.risk === risk).length
  const total = Math.min(scan.candidateTotal ?? scan.candidates.length, scan.candidates.length)
  const shown = Math.min(60, scan.candidates.length)
  p(`- 共发现 ${total} 项候选，下表显示前 ${shown} 项；A 级代表低风险，删除前仍需按「说明」操作。`)
  p(`- A 低风险：${cnt('safe')} 项，合计 **${sum('safe').toFixed(2)} GB**`)
  p(`- B 需确认：${cnt('review')} 项，合计 **${sum('review').toFixed(2)} GB**`)
  p(`- C 先核实：${cnt('unknown')} 项，合计 **${sum('unknown').toFixed(2)} GB**`)
  p()
  p('| # | 分级 | 类别 | 占用 | 路径 | 说明 |')
  p('|---:|---|---|---:|---|---|')
  scan.candidates.slice(0, 60).forEach((c, i) => {
    p(`| ${i + 1} | ${RISK_LABEL[c.risk]} | ${c.category} | **${fmtGB(c.bytes)}** | \`${c.path}\` | ${c.note} |`)
  })
  if (total > shown) p(`\n> 仅显示前 ${shown} 项，其余 ${total - shown} 项见 disk-cleanup.csv / .json。`)
  p()
  if (scan.large.length) {
    p(`## 三、大文件（≥ ${scan.options.largeFileMb} MB，前 30）`)
    p()
    p('| # | 大小 | 最后修改 | 路径 |')
    p('|---:|---:|---|---|')
    scan.large.slice(0, 30).forEach((f, i) => {
      p(`| ${i + 1} | ${fmtGB(f.bytes)} | ${when(f.mtime)} | \`${f.path}\` |`)
    })
    p()
  }
  p(`## 四、目录占用 TOP（深度 ${scan.options.depth}，前 30）`)
  p()
  p('| 目录 | 占用 | 文件数 |')
  p('|---|---:|---:|')
  for (const d of scan.dirsAtDepth.slice(0, 30)) {
    p(`| \`${d.key}\` | ${fmtGB(d.bytes)} | ${d.files.toLocaleString('en-US')} |`)
  }
  p()
  p('## 五、不要手动删除')
  p()
  if (scan.keep.length) {
    for (const k of scan.keep) {
      p(`- \`${k.path}\`（${fmtGB(k.bytes)}）— ${k.note}`)
    }
  } else {
    p('- 本次扫描范围内未发现这些系统保留目录（扫描的是子目录时属正常）。')
  }
  p()
  p('## 六、方法与限制')
  p()
  p('- 采用只读遍历，跳过符号链接/联接点，避免重复计数；无权限的目录计入「不可读」。')
  p('- 大小按文件逻辑长度累加；Windows 组件目录含硬链接，实际占用可能小于累加值。')
  p('- 未做病毒扫描、数字签名校验或文件内容分析；「来源不明」仅基于目录名与位置推断。')
  p('- 删除前请确认对应软件已退出；系统目录请使用系统自带清理工具（磁盘清理 / DISM）。')
  return lines.join('\n') + '\n'
}

export function buildHtml(scan) {
  const sum = (risk) => scan.candidates.filter((c) => c.risk === risk).reduce((a, c) => a + c.bytes, 0) / GB
  const cnt = (risk) => scan.candidates.filter((c) => c.risk === risk).length
  const rows = scan.candidates.slice(0, 200).map((c, i) => `
      <tr>
        <td class="rank">${i + 1}</td>
        <td><span class="risk r-${c.risk}">${esc(RISK_LABEL[c.risk])}</span></td>
        <td>${esc(c.category)}</td>
        <td class="size ${sizeClass(c.bytes)}">${fmtGB(c.bytes)}</td>
        <td class="path">${esc(c.path)}</td>
        <td class="note">${esc(c.note)}</td>
      </tr>`).join('')

  const topRows = scan.topDirs.slice(0, 12).map((d) => `
      <tr><td class="path">${esc(d.name)}</td><td class="size ${sizeClass(d.bytes)}">${fmtGB(d.bytes)}</td><td>${d.files.toLocaleString('en-US')}</td></tr>`).join('')

  const largeRows = scan.large.slice(0, 30).map((f, i) => `
      <tr><td class="rank">${i + 1}</td><td class="size ${sizeClass(f.bytes)}">${fmtGB(f.bytes)}</td><td>${esc(when(f.mtime))}</td><td class="path">${esc(f.path)}</td></tr>`).join('')

  const candidateTotal = scan.candidateTotal ?? scan.candidates.length
  const shownRows = Math.min(200, scan.candidates.length)

  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(scan.root)} 磁盘清理扫描报告</title>
<style>
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body { margin: 0; padding: 28px 24px 60px; font: 14px/1.6 "Microsoft YaHei", "Segoe UI", system-ui, sans-serif; color: #1f2937; background: #f5f7fb; }
  .wrap { max-width: 1180px; margin: 0 auto; }
  h1 { font-size: 24px; margin: 0 0 6px; color: #0f172a; }
  .meta { color: #64748b; font-size: 13px; margin-bottom: 20px; }
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-bottom: 22px; }
  .card { background: #fff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 14px 16px; box-shadow: 0 1px 2px rgba(15,23,42,.04); }
  .card .k { color: #64748b; font-size: 12px; }
  .card .v { font-size: 22px; font-weight: 700; margin-top: 2px; }
  .card .v.red { color: #b91c1c; }
  .card .v.amber { color: #b45309; }
  .card .v.green { color: #15803d; }
  h2 { font-size: 17px; margin: 30px 0 10px; color: #0f172a; }
  table { width: 100%; border-collapse: collapse; background: #fff; border: 1px solid #e2e8f0; border-radius: 12px; overflow: hidden; }
  .tablewrap { overflow-x: auto; -webkit-overflow-scrolling: touch; }
  th { background: #1f3864; color: #fff; text-align: left; font-weight: 600; padding: 10px 12px; font-size: 13px; white-space: nowrap; }
  td { padding: 9px 12px; border-top: 1px solid #eef2f7; vertical-align: middle; }
  tr:nth-child(even) td { background: #f8fafc; }
  .rank { color: #94a3b8; text-align: right; width: 46px; }
  .path { font-family: Consolas, "Cascadia Mono", monospace; font-size: 12.5px; color: #334155; word-break: break-all; }
  .note { color: #64748b; font-size: 12.5px; }
  .size { font-family: Consolas, "Cascadia Mono", monospace; font-weight: 700; text-align: right; white-space: nowrap; border-radius: 6px; }
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
  @media (max-width: 640px) {
    body { padding: 18px 12px 40px; }
    table { min-width: 640px; }
    .note { display: none; }
    .path { font-size: 11.5px; }
  }
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
  }
</style>
</head>
<body>
<div class="wrap">
  <h1>${esc(scan.root)} 磁盘清理扫描报告</h1>
  <div class="meta">生成时间 ${esc(when(scan.scannedAt))} · 耗时 ${scan.elapsedSec.toFixed(1)} 秒 · 文件 ${scan.totals.files.toLocaleString('en-US')} 个 · 不可读 ${scan.totals.errors} 处 · 只读扫描，未改动任何文件</div>

  <div class="cards">
    <div class="card"><div class="k">卷容量 / 可用</div><div class="v">${scan.volume ? (scan.volume.totalBytes / GB).toFixed(0) + ' GB / ' + (scan.volume.freeBytes / GB).toFixed(1) + ' GB' : '未知'}</div></div>
    <div class="card"><div class="k">可枚举文件总量</div><div class="v">${(scan.totals.bytes / GB).toFixed(2)} GB</div></div>
    <div class="card"><div class="k">A 低风险（${cnt('safe')} 项）</div><div class="v green">${sum('safe').toFixed(2)} GB</div></div>
    <div class="card"><div class="k">B 需确认（${cnt('review')} 项）</div><div class="v amber">${sum('review').toFixed(2)} GB</div></div>
    <div class="card"><div class="k">C 先核实（${cnt('unknown')} 项）</div><div class="v red">${sum('unknown').toFixed(2)} GB</div></div>
  </div>

  <h2>可清理候选（按占用从大到小）</h2>
  <div class="meta">共 ${candidateTotal} 项，显示前 ${shownRows} 项；A 级表示低风险，删除前仍请按「说明」操作。</div>
  <div class="tablewrap">
  <table>
    <thead><tr><th>#</th><th>分级</th><th>类别</th><th style="text-align:right">占用大小</th><th>路径</th><th>说明</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>
  </div>

  <h2>顶层目录占用</h2>
  <div class="tablewrap">
  <table>
    <thead><tr><th>目录</th><th style="text-align:right">占用</th><th>文件数</th></tr></thead>
    <tbody>${topRows}</tbody>
  </table>
  </div>

  <h2>大文件（≥ ${scan.options.largeFileMb} MB，前 30）</h2>
  <div class="tablewrap">
  <table>
    <thead><tr><th>#</th><th style="text-align:right">大小</th><th>最后修改</th><th>路径</th></tr></thead>
    <tbody>${largeRows}</tbody>
  </table>
  </div>

  <h2>不要手动删除</h2>
  <ul>
    ${scan.keep.length
      ? scan.keep.map((k) => `<li><code>${esc(k.path)}</code>（${fmtGB(k.bytes)}）— ${esc(k.note)}</li>`).join('\n    ')
      : '<li>本次扫描范围内未发现这些系统保留目录（扫描子目录时属正常）。</li>'}
  </ul>

  <div class="foot">
    只读遍历，跳过符号链接/联接点；大小按逻辑长度累加，Windows 组件目录含硬链接可能偏大。未做病毒扫描或数字签名校验。「来源不明」仅基于目录名与位置推断。
  </div>
</div>
</body>
</html>
`
}

export function buildCsv(scan) {
  const header = ['序号', '分级', '类别', '路径', '大小GB', '建议', '说明']
  const q = (v) => `"${String(v).replace(/"/g, '""')}"`
  const rows = scan.candidates.map((c, i) => [
    i + 1,
    RISK_LABEL[c.risk],
    c.category,
    c.path,
    (c.bytes / GB).toFixed(2),
    c.advice,
    c.note
  ].map(q).join(','))
  return '\uFEFF' + [header.map(q).join(','), ...rows].join('\r\n') + '\r\n'
}

export function buildJson(scan) {
  return JSON.stringify({
    root: scan.root,
    scannedAt: scan.scannedAt,
    elapsedSec: scan.elapsedSec,
    totals: scan.totals,
    volume: scan.volume,
    topDirs: scan.topDirs,
    dirsAtDepth: scan.dirsAtDepth.slice(0, 300),
    large: scan.large,
    candidates: scan.candidates,
    keep: scan.keep,
    extensions: scan.extensions,
    options: scan.options
  }, null, 2)
}

export function writeReports(scan, outputDir) {
  fs.mkdirSync(outputDir, { recursive: true })
  const base = path.join(outputDir, 'disk-cleanup')
  const files = {
    md: base + '.md',
    html: base + '.html',
    csv: base + '.csv',
    json: base + '.json'
  }
  fs.writeFileSync(files.md, buildMarkdown(scan), 'utf8')
  fs.writeFileSync(files.html, buildHtml(scan), 'utf8')
  fs.writeFileSync(files.csv, buildCsv(scan), 'utf8')
  fs.writeFileSync(files.json, buildJson(scan), 'utf8')
  return files
}
