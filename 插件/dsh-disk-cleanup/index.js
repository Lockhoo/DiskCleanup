import os from 'node:os'
import path from 'node:path'
import fs from 'node:fs'
import { randomUUID } from 'node:crypto'
import { spawn } from 'node:child_process'
import { Worker } from 'node:worker_threads'
import { driveTag, stamp } from './lib/scan.js'

export const name = 'dsh-disk-cleanup'
export const inject = ['tools']

const WORKER_URL = new URL('./lib/worker.js', import.meta.url)
const isWindows = process.platform === 'win32'
const ROUTE_PREFIX = '/plugin/disk-cleanup'

/** Finished scans kept for status and report reads, most recent last. */
const jobs = new Map()
const reportHits = new Map()
const MAX_JOBS = 10
const STORE_FILE = path.join(os.homedir(), 'Documents', 'DSH-Scan', '.jobs.json')

function persistJobs() {
  try {
    fs.mkdirSync(path.dirname(STORE_FILE), { recursive: true })
    const list = [...jobs.values()].map((j) => ({
      id: j.id,
      state: j.state,
      startedAt: j.startedAt,
      error: j.error,
      summary: j.summary
    }))
    fs.writeFileSync(STORE_FILE, JSON.stringify(list))
  } catch { /* persistence is best-effort */ }
}

function restoreJobs() {
  try {
    const raw = JSON.parse(fs.readFileSync(STORE_FILE, 'utf8'))
    if (!Array.isArray(raw)) return
    for (const item of raw) {
      if (!item || typeof item.id !== 'string') continue
      const job = { id: item.id, state: item.state, startedAt: item.startedAt, summary: item.summary ?? null, error: item.error ?? null }
      if (job.state === 'running') {
        job.state = 'error'
        job.error = '扫描被中断：DSH 重启时后台任务被终止，请重新扫描'
      }
      jobs.set(job.id, job)
    }
  } catch { /* no previous jobs */ }
}

restoreJobs()

function defaultOutputDir(root) {
  return path.join(os.homedir(), 'Documents', 'DSH-Scan', `${driveTag(root)}-${stamp()}`)
}

function runWorker(options, outputDir) {
  return new Promise((resolve, reject) => {
    let settled = false
    let worker
    const finish = (fn, value) => {
      if (settled) return
      settled = true
      try { worker && worker.terminate() } catch { /* ignore */ }
      fn(value)
    }
    try {
      worker = new Worker(WORKER_URL, { workerData: { options, outputDir } })
    } catch (error) {
      reject(error)
      return
    }
    worker.once('message', (message) => {
      if (message && message.ok) finish(resolve, message.summary)
      else finish(reject, new Error((message && message.error) || 'disk scan failed'))
    })
    worker.once('error', (error) => finish(reject, error))
    worker.once('exit', (code) => {
      if (!settled) finish(reject, new Error(`disk scan worker exited unexpectedly (code ${code})`))
    })
  })
}

function runningJob() {
  for (const job of jobs.values()) if (job.state === 'running') return job
  return undefined
}

function pruneJobs() {
  const done = [...jobs.values()].filter((j) => j.state !== 'running')
  while (jobs.size > MAX_JOBS && done.length > 0) jobs.delete(done.shift().id)
}

function startJob(args) {
  const root = String(args.path || (isWindows ? 'C:\\' : '/')).trim()
  const outputDir = String(args.output_dir || defaultOutputDir(root)).trim()
  const depthRaw = Number(args.depth ?? 2)
  const largeRaw = Number(args.large_file_mb ?? 300)
  const options = {
    root,
    depth: Number.isFinite(depthRaw) ? depthRaw : 2,
    largeFileMb: Number.isFinite(largeRaw) ? largeRaw : 300
  }
  const job = { id: randomUUID(), state: 'running', startedAt: Date.now(), summary: null, error: null }
  jobs.set(job.id, job)
  pruneJobs()
  persistJobs()
  runWorker(options, outputDir)
    .then((summary) => {
      job.state = 'done'
      job.summary = summary
      persistJobs()
    })
    .catch((error) => {
      job.state = 'error'
      job.error = String((error && error.message) || error)
      persistJobs()
    })
  return job
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = []
    let size = 0
    req.on('data', (chunk) => {
      size += chunk.length
      if (size > 64 * 1024) {
        reject(new Error('请求体过大'))
        req.destroy()
        return
      }
      chunks.push(chunk)
    })
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')))
    req.on('error', reject)
  })
}

function browserCandidates() {
  const list = []
  if (process.platform === 'win32') {
    const pf = process.env.ProgramFiles || 'C:\\Program Files'
    const pf86 = process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)'
    list.push(
      pf86 + '\\Microsoft\\Edge\\Application\\msedge.exe',
      pf + '\\Microsoft\\Edge\\Application\\msedge.exe',
      pf + '\\Google\\Chrome\\Application\\chrome.exe',
      pf86 + '\\Google\\Chrome\\Application\\chrome.exe'
    )
  }
  return list.filter((candidate) => {
    try { return fs.existsSync(candidate) } catch { return false }
  })
}

function openUrlInBrowser(target) {
  const launchers = []
  for (const browser of browserCandidates()) launchers.push({ command: browser, args: ['--new-window', target] })
  if (process.platform === 'win32') launchers.push({ command: 'cmd.exe', args: ['/c', 'start', '', target] })
  else if (process.platform === 'darwin') launchers.push({ command: 'open', args: [target] })
  else launchers.push({ command: 'xdg-open', args: [target] })

  return new Promise((resolve) => {
    const attempt = (index) => {
      if (index >= launchers.length) {
        resolve(false)
        return
      }
      const { command, args } = launchers[index]
      try {
        const child = spawn(command, args, { detached: true, stdio: 'ignore', windowsHide: true })
        child.on('error', () => attempt(index + 1))
        child.unref()
        resolve(true)
      } catch {
        attempt(index + 1)
      }
    }
    attempt(0)
  })
}

function sendJson(res, status, value) {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' })
  res.end(JSON.stringify(value))
}

function serveReport(res, id) {
  const job = jobs.get(id)
  if (!job || job.state !== 'done') {
    res.writeHead(409, { 'content-type': 'text/plain; charset=utf-8' })
    res.end('报告尚未生成')
    return
  }
  const htmlPath = job.summary?.outputs?.html
  if (!htmlPath || !fs.existsSync(htmlPath)) {
    res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' })
    res.end('报告文件不存在')
    return
  }
  reportHits.set(id, (reportHits.get(id) || 0) + 1)
  res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' })
  res.end(fs.readFileSync(htmlPath))
}

async function handleHttp(req, res) {
  let url
  try {
    url = new URL(req.url || '/', 'http://local')
  } catch {
    sendJson(res, 400, { error: 'bad request' })
    return
  }
  const reportPrefix = ROUTE_PREFIX + '/report/'
  if (req.method === 'GET' && url.pathname.startsWith(reportPrefix)) {
    serveReport(res, decodeURIComponent(url.pathname.slice(reportPrefix.length)))
    return
  }
  const action = url.searchParams.get('action') || 'status'
  try {
    if (req.method === 'POST' && action === 'scan') {
      const busy = runningJob()
      if (busy) {
        sendJson(res, 409, { error: '已有扫描正在进行，请等待完成' })
        return
      }
      const raw = await readBody(req)
      let args = {}
      if (raw.trim() !== '') args = JSON.parse(raw)
      const job = startJob(args)
      sendJson(res, 200, { id: job.id, state: job.state, startedAt: job.startedAt })
      return
    }
    if (req.method === 'GET' && action === 'list') {
      sendJson(res, 200, {
        jobs: [...jobs.values()]
          .sort((a, b) => b.startedAt - a.startedAt)
          .map((j) => ({
            id: j.id,
            state: j.state,
            startedAt: j.startedAt,
            elapsedSec: Math.round((Date.now() - j.startedAt) / 100) / 10,
            root: j.summary?.root || null,
            error: j.error || null
          }))
      })
      return
    }
    if (req.method === 'GET' && action === 'status') {
      const job = jobs.get(String(url.searchParams.get('id') || ''))
      if (!job) {
        sendJson(res, 404, { error: '任务不存在或已过期' })
        return
      }
      sendJson(res, 200, {
        id: job.id,
        state: job.state,
        startedAt: job.startedAt,
        elapsedSec: Math.round((Date.now() - job.startedAt) / 100) / 10,
        reportHits: reportHits.get(job.id) || 0,
        summary: job.summary,
        error: job.error
      })
      return
    }
    if (req.method === 'POST' && action === 'open') {
      const job = jobs.get(String(url.searchParams.get('id') || ''))
      if (!job || job.state !== 'done') {
        sendJson(res, 409, { error: '报告尚未生成' })
        return
      }
      const htmlPath = job.summary?.outputs?.html
      if (!htmlPath || !fs.existsSync(htmlPath)) {
        sendJson(res, 404, { error: '报告文件不存在' })
        return
      }
      const proto = req.socket && req.socket.encrypted ? 'https' : 'http'
      const host = req.headers.host || '127.0.0.1'
      const reportUrl = proto + '://' + host + ROUTE_PREFIX + '/report/' + encodeURIComponent(job.id)
      const opened = await openUrlInBrowser(reportUrl)
      sendJson(res, opened ? 200 : 500, opened ? { ok: true, path: reportUrl } : { error: '无法启动默认浏览器' })
      return
    }
    if (req.method === 'GET' && action === 'report') {
      const job = jobs.get(String(url.searchParams.get('id') || ''))
      if (!job || job.state !== 'done') {
        res.writeHead(409, { 'content-type': 'text/plain; charset=utf-8' })
        res.end('报告尚未生成')
        return
      }
      const htmlPath = job.summary?.outputs?.html
      if (!htmlPath || !fs.existsSync(htmlPath)) {
        res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' })
        res.end('报告文件不存在')
        return
      }
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' })
      res.end(fs.readFileSync(htmlPath))
      return
    }
    sendJson(res, 400, { error: '未知操作' })
  } catch (error) {
    sendJson(res, 500, { error: String((error && error.message) || error) })
  }
}

const OUTPUT_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['root', 'scannedAt', 'elapsedSec', 'totalGB', 'files', 'dirs', 'errors', 'candidateCount', 'safeCount', 'reviewCount', 'unknownCount', 'safeGB', 'reviewGB', 'unknownGB', 'topDirs', 'topCandidates', 'outputs'],
  properties: {
    root: { type: 'string' },
    scannedAt: { type: 'string' },
    elapsedSec: { type: 'number' },
    totalGB: { type: 'number' },
    files: { type: 'integer' },
    dirs: { type: 'integer' },
    errors: { type: 'integer' },
    freeGB: { type: 'number' },
    volumeGB: { type: 'number' },
    candidateCount: { type: 'integer' },
    safeCount: { type: 'integer' },
    reviewCount: { type: 'integer' },
    unknownCount: { type: 'integer' },
    safeGB: { type: 'number' },
    reviewGB: { type: 'number' },
    unknownGB: { type: 'number' },
    topDirs: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['name', 'gb'],
        properties: { name: { type: 'string' }, gb: { type: 'number' } }
      }
    },
    topCandidates: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['path', 'gb', 'risk', 'category'],
        properties: {
          path: { type: 'string' },
          gb: { type: 'number' },
          risk: { type: 'string' },
          category: { type: 'string' }
        }
      }
    },
    outputs: {
      type: 'object',
      additionalProperties: false,
      required: ['md', 'html', 'csv', 'json'],
      properties: {
        md: { type: 'string' },
        html: { type: 'string' },
        csv: { type: 'string' },
        json: { type: 'string' }
      }
    }
  }
}

export function apply(ctx) {
  ctx.tools.register({
    name: 'disk_cleanup_scan',
    description:
      'Scan a drive or folder read-only and produce a cleanup report: top-level usage, cache/temp/log candidates sorted by size, large files, suspicious leftovers, and a do-not-delete list. Writes Markdown, HTML, CSV, and JSON files and never deletes, moves, or modifies scanned files. Defaults to the C: drive on Windows.',
    parameters: {
      type: 'object',
      additionalProperties: false,
      properties: {
        path: {
          type: 'string',
          description: 'Drive or directory to scan, e.g. "C:\\\\" or "D:\\\\Projects". Defaults to C:\\\\ on Windows and / elsewhere.'
        },
        output_dir: {
          type: 'string',
          description: 'Directory that receives disk-cleanup.md/.html/.csv/.json. Defaults to <home>/Documents/DSH-Scan/<drive>-<timestamp>.'
        },
        depth: {
          type: 'integer',
          default: 2,
          description: 'Directory grouping depth (1-4) for the occupancy table. Default 2.'
        },
        large_file_mb: {
          type: 'integer',
          default: 300,
          description: 'Only report files at least this many MB. Default 300.'
        }
      }
    },
    output: {
      schema: OUTPUT_SCHEMA,
      render: (_args, value) => {
        const lines = [
          `Scanned ${value.root}: ${value.totalGB} GB in ${value.elapsedSec}s (${value.files.toLocaleString('en-US')} files, ${value.errors} unreadable).`,
          `Candidates: ${value.candidateCount} (A safe ${value.safeCount}/${value.safeGB} GB, B review ${value.reviewCount}/${value.reviewGB} GB, C unknown ${value.unknownCount}/${value.unknownGB} GB).`
        ]
        if (value.topCandidates.length) {
          lines.push('Largest candidates:')
          for (const c of value.topCandidates) lines.push(`- [${c.risk}] ${c.gb} GB  ${c.path}`)
        }
        lines.push(`Report: ${value.outputs.html}`)
        lines.push(`CSV: ${value.outputs.csv}`)
        return [{ type: 'text', text: lines.join('\n') }]
      }
    },
    async execute(args) {
      const root = String(args.path || (isWindows ? 'C:\\' : '/')).trim()
      const outputDir = String(args.output_dir || defaultOutputDir(root)).trim()
      const options = {
        root,
        depth: args.depth ?? 2,
        largeFileMb: args.large_file_mb ?? 300
      }
      return runWorker(options, outputDir)
    },
    presentCall: (args) => ({
      card: 'generic',
      title: 'Scan disk for cleanup',
      kind: 'other',
      rawInput: { path: args.path || (isWindows ? 'C:\\' : '/') }
    })
  })

  // UI-facing HTTP endpoints used by the sidebar panel (client.js).
  ctx.inject(['webServer'], (scope) => {
    scope.effect(
      () => scope.webServer.register({
        kind: 'prefix',
        path: ROUTE_PREFIX,
        handler: (req, res) => { handleHttp(req, res) }
      }),
      'disk-cleanup ui route'
    )
  })
}





