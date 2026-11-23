import { parentPort, workerData } from 'node:worker_threads'
import { scanTree, summarize } from './scan.js'
import { writeReports } from './report.js'

try {
  const scan = scanTree(workerData.options)
  const outputs = writeReports(scan, workerData.outputDir)
  parentPort.postMessage({ ok: true, summary: summarize(scan, outputs) })
} catch (error) {
  parentPort.postMessage({ ok: false, error: (error && error.stack) || String(error) })
}
