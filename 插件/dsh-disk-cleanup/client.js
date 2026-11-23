window.__ModuleLoader__.load({
  id: 'dsh-disk-cleanup',
  factory(require) {
    const React = require('react')
    const h = React.createElement
    const { useState, useEffect, useRef, useCallback } = React

    const API = '/plugin/disk-cleanup'
    const LAST_JOB = 'dsh-disk-cleanup:last-job'

    const S = {
      root: { display: 'flex', flexDirection: 'column', gap: 14, padding: '18px 16px 28px', overflowY: 'auto', height: '100%', color: 'var(--dsw-alias-label-primary, CanvasText)' },
      h1: { fontSize: 16, fontWeight: 650, margin: 0 },
      sub: { fontSize: 12, lineHeight: 1.6, margin: 0, opacity: 0.65 },
      card: { border: '1px solid var(--dsw-alias-border-l2, rgba(127,127,127,.28))', borderRadius: 10, padding: 12, background: 'var(--dsw-alias-bg-layer, rgba(127,127,127,.06))' },
      label: { fontSize: 12, fontWeight: 600, display: 'block', marginBottom: 4, opacity: 0.85 },
      input: { width: '100%', boxSizing: 'border-box', fontSize: 13, padding: '7px 9px', borderRadius: 7, border: '1px solid var(--dsw-alias-border-l2, rgba(127,127,127,.35))', background: 'var(--dsw-alias-bg-base, rgba(127,127,127,.10))', color: 'inherit', outline: 'none' },
      row: { display: 'flex', gap: 10, alignItems: 'flex-end' },
      btn: { fontSize: 13, fontWeight: 600, padding: '8px 14px', borderRadius: 7, border: 'none', cursor: 'pointer', color: '#fff', background: 'var(--dsw-alias-state-business-primary, #2563eb)' },
      btnGhost: { fontSize: 13, fontWeight: 600, padding: '7px 12px', borderRadius: 7, cursor: 'pointer', color: 'inherit', background: 'transparent', border: '1px solid var(--dsw-alias-border-l2, rgba(127,127,127,.35))' },
      err: { fontSize: 12, color: 'var(--dsw-alias-state-error-primary, #b91c1c)', lineHeight: 1.5 },
      statRow: { display: 'grid', gridTemplateColumns: 'repeat(3, minmax(0,1fr))', gap: 8 },
      stat: { border: '1px solid var(--dsw-alias-border-l2, rgba(127,127,127,.25))', borderRadius: 8, padding: '8px 10px' },
      statK: { fontSize: 11, opacity: 0.6, whiteSpace: 'nowrap' },
      statV: { fontSize: 15, fontWeight: 700, marginTop: 2, whiteSpace: 'nowrap' },
      cand: { display: 'flex', justifyContent: 'space-between', gap: 8, fontSize: 12, padding: '5px 0', borderTop: '1px dashed var(--dsw-alias-border-l2, rgba(127,127,127,.22))' },
      candPath: { overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', direction: 'rtl', textAlign: 'left', flex: 1, opacity: 0.85 },
      candSize: { fontWeight: 700, whiteSpace: 'nowrap' },
      pill: { fontSize: 10, fontWeight: 700, padding: '1px 6px', borderRadius: 999, whiteSpace: 'nowrap' },
      foot: { fontSize: 11, lineHeight: 1.6, opacity: 0.5 },
      spin: { width: 14, height: 14, borderRadius: '50%', border: '2px solid rgba(127,127,127,.35)', borderTopColor: 'var(--dsw-alias-state-business-primary, #2563eb)', animation: 'dsh-disk-spin .8s linear infinite' }
    }

    const RISK = {
      safe: { label: 'A 低风险', color: '#1b5e20', bg: '#e8f5e9' },
      review: { label: 'B 需确认', color: '#b45309', bg: '#fff8e1' },
      unknown: { label: 'C 先核实', color: '#b71c1c', bg: '#fdecea' }
    }

    function fmtGb(v) {
      const n = Number(v) || 0
      return n >= 0.01 ? n.toFixed(2) + ' GB' : '0 GB'
    }

    function Panel() {
      const [scanPath, setScanPath] = useState('C:\\')
      const [threshold, setThreshold] = useState('300')
      const [job, setJob] = useState(null)
      const [status, setStatus] = useState(null)
      const [error, setError] = useState('')
      const [busy, setBusy] = useState(false)
      const [opening, setOpening] = useState(false)
      const [notice, setNotice] = useState('')
      const [now, setNow] = useState(Date.now())
      const timer = useRef(null)

      // Restore the last job id so a panel remount can keep showing its result.
      useEffect(() => {
        try {
          const saved = JSON.parse(localStorage.getItem(LAST_JOB) || 'null')
          if (saved && saved.id) setJob({ id: saved.id, state: 'running', startedAt: saved.startedAt || Date.now() })
        } catch { /* ignore */ }
      }, [])

      useEffect(() => {
        timer.current = setInterval(() => setNow(Date.now()), 1000)
        return () => clearInterval(timer.current)
      }, [])

      useEffect(() => {
        if (!job || !job.id || job.state === 'done' || job.state === 'error') return
        let alive = true
        let iv
        const poll = async () => {
          try {
            const res = await fetch(`${API}?action=status&id=${encodeURIComponent(job.id)}`, { cache: 'no-store' })
            const data = await res.json().catch(() => ({}))
            if (!alive) return
            if (res.status === 404) {
              setJob({ id: job.id, state: 'lost', startedAt: job.startedAt })
              try { localStorage.removeItem(LAST_JOB) } catch { /* ignore */ }
              setNotice('上次的扫描任务已失效（DSH 重启会终止后台扫描），请重新扫描。')
              return
            }
            if (!res.ok) throw new Error(data.error || '状态查询失败')
            setStatus(data)
            if (data.state === 'done' || data.state === 'error') {
              setJob({ id: job.id, state: data.state, startedAt: data.startedAt })
              try { localStorage.setItem(LAST_JOB, JSON.stringify({ id: job.id, startedAt: data.startedAt })) } catch { /* ignore */ }
            }
          } catch (e) {
            if (alive) setError(String((e && e.message) || e))
          }
        }
        poll()
        iv = setInterval(poll, 2000)
        return () => { alive = false; clearInterval(iv) }
      }, [job && job.id, job && job.state])

      const start = useCallback(async () => {
        setError('')
        setNotice('')
        setStatus(null)
        setJob(null)
        setBusy(true)
        try {
          const res = await fetch(`${API}?action=scan`, {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ path: scanPath, large_file_mb: Number(threshold) || 300 })
          })
          const data = await res.json().catch(() => ({}))
          if (!res.ok) throw new Error(data.error || '启动扫描失败')
          const j = { id: data.id, state: 'running', startedAt: data.startedAt }
          setJob(j)
          try { localStorage.setItem(LAST_JOB, JSON.stringify({ id: j.id, startedAt: j.startedAt })) } catch { /* ignore */ }
        } catch (e) {
          setError(String((e && e.message) || e) + '（如果页面不是通过 http:// 打开，宿主接口不可用）')
        } finally {
          setBusy(false)
        }
      }, [scanPath, threshold])

      const openReport = useCallback(async () => {
        if (!job || !job.id) return
        setOpening(true)
        setNotice('')
        try {
          const res = await fetch(`${API}?action=open&id=${encodeURIComponent(job.id)}`, { method: 'POST' })
          const data = await res.json().catch(() => ({}))
          if (!res.ok) throw new Error(data.error || '打开失败')
          setNotice('已用系统默认浏览器打开完整报告')
        } catch (e) {
          const path = status && status.summary && status.summary.outputs ? status.summary.outputs.html : ''
          setNotice('打开失败：' + ((e && e.message) || e) + (path ? '。可手动打开：' + path : ''))
        } finally {
          setOpening(false)
        }
      }, [job && job.id, status])

      const running = job && job.state === 'running'
      const lost = job && job.state === 'lost'
      const done = status && status.state === 'done' && status.summary
      const failed = (status && status.state === 'error') || job && job.state === 'error'
      const elapsed = running && job.startedAt ? Math.max(0, Math.floor((now - job.startedAt) / 1000)) : (status && status.elapsedSec) || 0

      return h('div', { style: S.root },
        h('style', null, '@keyframes dsh-disk-spin{to{transform:rotate(360deg)}}'),
        h('div', null,
          h('h1', { style: S.h1 }, '磁盘清理扫描'),
          h('p', { style: S.sub }, '只读扫描，不会删除或移动文件。扫描在后台运行，可离开本页。')
        ),
        h('div', { style: S.card },
          h('div', { style: { marginBottom: 10 } },
            h('label', { style: S.label }, '扫描路径'),
            h('input', {
              style: S.input,
              value: scanPath,
              onChange: (e) => setScanPath(e.target.value),
              placeholder: 'C:\\',
              spellCheck: false,
              disabled: !!running
            })
          ),
          h('div', { style: { marginBottom: 12 } },
            h('label', { style: S.label }, '大文件阈值（MB）'),
            h('input', {
              style: S.input,
              value: threshold,
              onChange: (e) => setThreshold(e.target.value.replace(/[^0-9]/g, '')),
              inputMode: 'numeric',
              disabled: !!running
            })
          ),
          h('button', { style: S.btn, onClick: start, disabled: busy || !!running },
            running ? '扫描中…' : busy ? '启动中…' : '开始扫描'
          )
        ),
        error ? h('div', { style: S.err }, error) : null,
        running ? h('div', { style: S.card },
          h('div', { style: { display: 'flex', alignItems: 'center', gap: 8, fontSize: 13 } },
            h('span', { style: S.spin }),
            h('span', null, `正在扫描 ${scanPath}，已用时 ${elapsed} 秒`)
          ),
          h('p', { style: { ...S.sub, marginTop: 8 } }, '首次扫描大容量磁盘通常需要 5–15 分钟，进度取决于文件数量与杀毒软件。')
        ) : null,
        failed ? h('div', { style: S.err }, '扫描失败：' + ((status && status.error) || (job && job.state === 'error' ? '请重试' : ''))) : null,
        lost ? h('div', { style: S.card },
          h('p', { style: { ...S.sub, marginTop: 0 } }, '上次任务已失效：DSH 重启会终止后台扫描，任务记录也会丢失。'),
          h('button', { style: S.btn, onClick: start }, '重新扫描')
        ) : null,
        done ? h('div', { style: S.card },
          h('div', null,
            h('div', { style: { fontSize: 12, opacity: 0.65, marginBottom: 8 } },
              `${done.root} · ${done.files.toLocaleString('zh-CN')} 个文件 · 耗时 ${done.elapsedSec} 秒 · 不可读 ${done.errors} 处`
            ),
            h('div', { style: S.statRow },
              h('div', { style: S.stat },
                h('div', { style: S.statK }, '卷可用'),
                h('div', { style: S.statV }, done.freeGB == null ? '—' : fmtGb(done.freeGB))
              ),
              h('div', { style: S.stat },
                h('div', { style: S.statK }, 'A 低风险'),
                h('div', { style: { ...S.statV, color: RISK.safe.color } }, fmtGb(done.safeGB))
              ),
              h('div', { style: S.stat },
                h('div', { style: S.statK }, 'B 需确认'),
                h('div', { style: { ...S.statV, color: RISK.review.color } }, fmtGb(done.reviewGB))
              )
            ),
            h('div', { style: { ...S.statRow, marginTop: 8 } },
              h('div', { style: S.stat },
                h('div', { style: S.statK }, 'C 先核实'),
                h('div', { style: { ...S.statV, color: RISK.unknown.color } }, fmtGb(done.unknownGB))
              ),
              h('div', { style: S.stat },
                h('div', { style: S.statK }, '候选总数'),
                h('div', { style: S.statV }, String(done.candidateCount))
              ),
              h('div', { style: S.stat },
                h('div', { style: S.statK }, '可枚举文件'),
                h('div', { style: S.statV }, fmtGb(done.totalGB))
              )
            )
          ),
          (done.topCandidates || []).length ? h('div', { style: { marginTop: 12 } },
            h('div', { style: { ...S.label, marginBottom: 4 } }, '占用最大的候选'),
            ...done.topCandidates.slice(0, 6).map((c, i) => h('div', { key: i, style: S.cand },
              h('span', {
                style: { ...S.pill, color: (RISK[c.risk] || RISK.safe).color, background: (RISK[c.risk] || RISK.safe).bg }
              }, (RISK[c.risk] || RISK.safe).label),
              h('span', { style: S.candPath, title: c.path }, c.path),
              h('span', { style: S.candSize }, fmtGb(c.gb))
            ))
          ) : null,
          h('div', { style: { display: 'flex', gap: 8, marginTop: 14, flexWrap: 'wrap' } },
            h('button', {
              style: S.btn,
              onClick: openReport,
              disabled: opening
            }, opening ? '正在打开…' : '打开完整报告'),
            h('a', {
              href: `${API}/report/${encodeURIComponent(job.id)}`,
              target: '_blank',
              rel: 'noopener noreferrer',
              style: { ...S.btnGhost, textDecoration: 'none', display: 'inline-block' }
            }, '在标签页中打开'),
            h('button', { style: S.btnGhost, onClick: start, disabled: busy }, '重新扫描')
          ),
          notice ? h('p', { style: { ...S.foot, marginTop: 8, color: notice.startsWith('打开失败') ? 'var(--dsw-alias-state-error-primary, #b91c1c)' : 'inherit', opacity: notice.startsWith('打开失败') ? 1 : 0.7 } }, notice) : null,
          h('p', { style: { ...S.foot, marginTop: 10 } }, `报告：${done.outputs.html}`)
        ) : null,
        h('p', { style: S.foot },
          'A 低风险：缓存/临时/日志类，删除前仍需按报告说明操作；B 需确认：个人数据；C 先核实：来源不明。系统目录请使用磁盘清理或 DISM。'
        )
      )
    }

    return {
      inject: ['slots'],
      apply(ctx) {
        ctx.effect(() => ctx.inject(['sidebarRightTabs'], (scope) => {
          const disposeType = scope.sidebarRightTabs.register({
            id: 'dsh-disk-cleanup',
            kind: 'dsh-disk-cleanup',
            title: () => '磁盘扫描',
            guide: [{
              id: 'dsh-disk-cleanup',
              order: 40,
              title: () => '磁盘扫描',
              description: () => '扫描磁盘并生成清理报告'
            }]
          })
          const disposeBody = scope.slots.inject('sidebar.right.pane.tab', () => scope.slots.register({
            name: 'sidebar.right.pane.tab',
            key: 'dsh-disk-cleanup'
          }, Panel))
          return () => {
            disposeBody()
            disposeType()
          }
        }), 'disk-cleanup sidebar tab')
      }
    }
  }
})
