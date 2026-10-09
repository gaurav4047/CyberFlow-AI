import { useCallback, useEffect, useState } from 'react'
import {
  Activity,
  AlertCircle,
  ArrowDownRight,
  ArrowRight,
  CheckCircle2,
  ChevronDown,
  CircleHelp,
  FileText,
  Fingerprint,
  Gauge,
  LayoutDashboard,
  LoaderCircle,
  LockKeyhole,
  Play,
  Radar,
  Settings,
  Sparkle,
  Shield,
  Sparkles,
  TerminalSquare,
  Workflow,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { Link, NavLink, Navigate, Route, Routes, useLocation } from 'react-router-dom'
import type { FormEvent } from 'react'
import { BugBountyPage, SocAnalystPage, HistoryPage, ReportsPage, CommandRouter } from './Workspaces'

type Health = {
  status: string
  service: string
  database: string
  response_time_ms: number
}
type Overview = { total_investigations: number; ctf_investigations: number; bug_bounty_reports: number; soc_investigations: number; total_reports: number; recent_activity: Array<{ id: string; title: string; agent: string; created_at: string; status: string; severity: string | null; summary: string }> }

type CtfCategory = 'web' | 'crypto' | 'reverse' | 'forensics' | 'pwn' | 'misc' | 'osint' | 'mobile'

type CtfInput = {
  challenge_title: string
  challenge_description: string
  category: CtfCategory
  difficulty: 'unknown' | 'beginner' | 'intermediate' | 'advanced'
  challenge_artifacts: string
  user_question: string
  command_input: string
}

type CtfAnalysis = {
  mode: 'ai' | 'demo'
  label: string
  result: string
  model?: string | null
  report_markdown?: string
  report_json?: Record<string, unknown>
}

type CtfDemo = CtfInput & { analysis: CtfAnalysis }

type NavigationItem = {
  label: string
  path: string
  icon: LucideIcon
}

const primaryNav: NavigationItem[] = [
  { label: 'Dashboard', path: '/', icon: LayoutDashboard },
]

const workspaceNav: NavigationItem[] = [
  { label: 'CTF Analyst', path: '/ctf-analyst', icon: TerminalSquare },
  { label: 'Bug Bounty', path: '/bug-bounty', icon: Fingerprint },
  { label: 'SOC Analyst', path: '/soc-analyst', icon: Radar },
]

const libraryNav: NavigationItem[] = [
  { label: 'Investigation History', path: '/history', icon: Workflow },
  { label: 'Reports', path: '/reports', icon: FileText },
]

const pageDetails: Record<string, { eyebrow: string; title: string; description: string; icon: LucideIcon; tag: string }> = {
  '/ctf-analyst': {
    eyebrow: 'WORKSPACE / ANALYSIS',
    title: 'CTF Analyst',
    description: 'Work through challenge artifacts and organize your security research in one place.',
    icon: TerminalSquare,
    tag: 'CHALLENGE WORKSPACE',
  },
  '/bug-bounty': {
    eyebrow: 'WORKSPACE / REPORTING',
    title: 'Bug Bounty',
    description: 'Prepare a clear, reproducible vulnerability report for your next responsible disclosure.',
    icon: Fingerprint,
    tag: 'REPORT WORKSPACE',
  },
  '/soc-analyst': {
    eyebrow: 'WORKSPACE / TRIAGE',
    title: 'SOC Analyst',
    description: 'Review security alerts and bring the context needed to start an investigation.',
    icon: Radar,
    tag: 'ALERT WORKSPACE',
  },
  '/history': {
    eyebrow: 'YOUR WORK / ACTIVITY',
    title: 'Investigation history',
    description: 'Return to investigations you have worked on across your CyberFlow workspace.',
    icon: Activity,
    tag: 'INVESTIGATION LOG',
  },
  '/reports': {
    eyebrow: 'YOUR WORK / OUTPUTS',
    title: 'Reports',
    description: 'Security reports you create will be collected here for easy access.',
    icon: FileText,
    tag: 'REPORT LIBRARY',
  },
}

async function requestHealth(): Promise<Health> {
  const response = await fetch('/api/health')
  if (!response.ok) throw new Error(`Health check returned ${response.status}`)
  return response.json() as Promise<Health>
}

async function requestCtfAnalysis(input: CtfInput): Promise<CtfAnalysis> {
  let response: Response
  try {
    response = await fetch('/api/ctf/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(input),
    })
  } catch {
    throw new Error('Could not reach the CyberFlow backend. Start FastAPI and try again.')
  }
  let data: CtfAnalysis | { detail?: string | Array<{ msg?: string }> }
  try {
    data = await response.json() as CtfAnalysis | { detail?: string | Array<{ msg?: string }> }
  } catch {
    throw new Error(response.ok ? 'The backend returned an unreadable analysis response.' : `The backend returned HTTP ${response.status}. Check the FastAPI terminal.`)
  }
  if (!response.ok) {
    const detail = 'detail' in data ? data.detail : undefined
    const message = Array.isArray(detail) ? detail.map((issue) => issue.msg).filter(Boolean).join(' ') : detail
    throw new Error(message || `Analysis request failed (${response.status}).`)
  }
  return data as CtfAnalysis
}

async function requestCtfDemo(): Promise<CtfDemo> {
  let response: Response
  try {
    response = await fetch('/api/ctf/demo')
  } catch {
    throw new Error('Could not reach the CyberFlow backend. Start FastAPI and try again.')
  }
  let data: CtfDemo | { detail?: string }
  try {
    data = await response.json() as CtfDemo | { detail?: string }
  } catch {
    throw new Error(response.ok ? 'The backend returned an unreadable demo response.' : `The backend returned HTTP ${response.status}. Check the FastAPI terminal.`)
  }
  if (!response.ok) {
    throw new Error('detail' in data && data.detail ? data.detail : `Demo request failed (${response.status}).`)
  }
  return data as CtfDemo
}

function App() {
  const [health, setHealth] = useState<Health | null>(null)
  const [healthError, setHealthError] = useState(false)
  const [checking, setChecking] = useState(false)
  const [overview, setOverview] = useState<Overview | null>(null)
  const location = useLocation()

  const checkHealth = useCallback(async () => {
    setChecking(true)
    try {
      setHealth(await requestHealth())
      setHealthError(false)
    } catch {
      setHealth(null)
      setHealthError(true)
    } finally {
      setChecking(false)
    }
  }, [])

  const refreshOverview = useCallback(async () => {
    try {
      const response = await fetch('/api/overview')
      if (!response.ok) throw new Error('Overview request failed')
      setOverview(await response.json() as Overview)
    } catch {
      setOverview(null)
    }
  }, [])

  useEffect(() => {
    void checkHealth()
    void refreshOverview()
  }, [checkHealth, refreshOverview])

  const title = location.pathname === '/' ? 'Dashboard' : location.pathname === '/settings' ? 'Settings' : pageDetails[location.pathname]?.title ?? 'Dashboard'
  const isHealthy = health?.status === 'ok' && health.database === 'ok'

  return (
    <div className="app-shell min-h-screen">
      <aside className="sidebar">
        <Link to="/" className="brand" aria-label="CyberFlow AI dashboard">
          <span className="brand-mark"><Shield size={18} strokeWidth={2.2} /><span /></span>
          <span className="brand-type">cyberflow<span>ai</span></span>
          <span className="brand-beta">BETA</span>
        </Link>

        <div className="workspace-switcher" aria-label="Current workspace">
          <span className="workspace-avatar">H</span>
          <span className="workspace-copy"><strong>CyberFlow AI</strong><small>Local workspace</small></span>
          <ChevronDown size={15} className="muted-icon" />
        </div>

        <div className="sidebar-section">
          <p className="section-label">OVERVIEW</p>
          <nav aria-label="Overview">
            {primaryNav.map((item) => <SidebarLink key={item.path} item={item} />)}
          </nav>
        </div>
        <div className="sidebar-section">
          <p className="section-label">WORKSPACE <span className="live-dot" /></p>
          <nav aria-label="Workspace tools">
            {workspaceNav.map((item) => <SidebarLink key={item.path} item={item} />)}
          </nav>
        </div>
        <div className="sidebar-section library-section">
          <p className="section-label">YOUR LIBRARY</p>
          <nav aria-label="Your library">
            {libraryNav.map((item) => <SidebarLink key={item.path} item={item} />)}
          </nav>
        </div>

        <div className="sidebar-spacer" />
        <div className="sidebar-bottom">
          <SidebarLink item={{ label: 'Settings', path: '/settings', icon: Settings }} />
          <div className="profile-row" aria-label="Signed in as Guest researcher">
            <span className="profile-avatar">GR</span>
            <span className="profile-copy"><strong>Guest researcher</strong><small>Local workspace</small></span>
            <ChevronDown size={14} className="muted-icon" />
          </div>
        </div>
      </aside>

      <main className="main-area">
        <header className="topbar">
          <div className="breadcrumbs"><span>Workspace</span><span className="crumb-slash">/</span><strong>{title}</strong></div>
          <div className="topbar-actions">
            <span className="system-indicator"><span className={isHealthy ? 'status-dot' : 'status-dot offline'} />{isHealthy ? 'All systems operational' : healthError ? 'API unavailable' : 'Checking systems'}</span>
            <span className="topbar-divider" />
            <span className="topbar-avatar">GR</span>
          </div>
        </header>

        <div className="page-content">
          <Routes>
            <Route path="/" element={<Dashboard health={health} healthError={healthError} checking={checking} onCheck={checkHealth} overview={overview} onRefreshOverview={refreshOverview} />} />
            <Route path="/ctf-analyst" element={<CtfAnalystPage />} />
            <Route path="/bug-bounty" element={<BugBountyPage />} />
            <Route path="/soc-analyst" element={<SocAnalystPage />} />
            <Route path="/history" element={<HistoryPage />} />
            <Route path="/reports" element={<ReportsPage />} />
            <Route path="/settings" element={<SettingsPage health={health} healthError={healthError} checking={checking} onCheck={checkHealth} />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
          <footer className="page-footer"><span>CYBERFLOW AI <span className="footer-separator">/</span> BUILT FOR THE FRONTLINES</span></footer>
        </div>
      </main>
    </div>
  )
}

function SidebarLink({ item }: { item: NavigationItem }) {
  const Icon = item.icon
  return <NavLink aria-label={item.label} end={item.path === '/'} to={item.path} className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}>
    <Icon size={17} strokeWidth={1.8} /><span>{item.label}</span>{item.label === 'CTF Analyst' && <span className="nav-new">NEW</span>}
  </NavLink>
}

function Dashboard({ health, healthError, checking, onCheck, overview, onRefreshOverview }: { health: Health | null; healthError: boolean; checking: boolean; onCheck: () => void; overview: Overview | null; onRefreshOverview: () => Promise<void> }) {
  const isHealthy = health?.status === 'ok' && health.database === 'ok'
  useEffect(() => { void onRefreshOverview() }, [onRefreshOverview])
  return <>
    <div className="welcome-row">
      <div>
        <div className="eyebrow"><span className="eyebrow-line" />THURSDAY, OCTOBER 09, 2026</div>
        <h1>Good morning, researcher<span className="title-period">.</span></h1>
        <p className="welcome-subtitle">Your security workspace is ready. Where would you like to begin?</p>
      </div>
      <div className="secure-badge"><span className="secure-icon"><LockKeyhole size={14} /></span><span><strong>PRIVATE WORKSPACE</strong><small>Your data stays yours</small></span></div>
    </div>

    <section className="hero-panel">
      <div className="hero-orb orb-one" /><div className="hero-orb orb-two" /><div className="hero-grid" />
      <div className="hero-content">
        <div className="hero-kicker"><Sparkles size={13} /> YOUR SECURITY OPERATIONS, IN FLOW</div>
        <h2>Think like an analyst.<br /><span>Move at the speed of security.</span></h2>
        <p>One focused workspace for finding flags, writing clear reports, and making sense of security alerts.</p>
        <div className="hero-foot"><span className="hero-status"><span className="status-dot" /> WORKSPACE ONLINE</span><span className="hero-foot-divider" /><span>BUILT FOR SECURITY RESEARCHERS</span></div>
      </div>
      <div className="hero-visual" aria-hidden="true">
        <div className="orbit orbit-a" /><div className="orbit orbit-b" /><div className="orbit orbit-c" />
        <div className="visual-core"><Shield size={36} strokeWidth={1.15} /><span className="core-spark">✳</span></div>
        <div className="visual-chip chip-one"><TerminalSquare size={15} /><span>WORKFLOW READY</span></div>
        <div className="visual-chip chip-two"><span className="status-dot" /><span>SECURE SESSION</span></div>
        <span className="visual-cross cross-one">+</span><span className="visual-cross cross-two">+</span>
      </div>
      <div className="hero-corner">CF<span>—</span>01</div>
    </section>

    <div className="section-heading tools-heading"><div><div className="eyebrow"><span className="eyebrow-line" />YOUR TOOLKIT</div><h2>Choose your workflow</h2></div><span className="heading-note">THREE SPECIALIZED WORKSPACES <span className="heading-note-count">03</span></span></div>
    <section className="tool-grid" aria-label="Security workspaces">
      <ToolCard number="01" icon={TerminalSquare} title="CTF Analyst" category="CHALLENGE INTELLIGENCE" description="Investigate challenge files, trace clues, and keep your CTF thinking organized." path="/ctf-analyst" accent="mint" />
      <ToolCard number="02" icon={Fingerprint} title="Bug Bounty" category="RESPONSIBLE DISCLOSURE" description="Structure vulnerability findings into reports that are clear and reproducible." path="/bug-bounty" accent="violet" />
      <ToolCard number="03" icon={Radar} title="SOC Analyst" category="THREAT TRIAGE" description="Bring alert details into focus and prepare for a deeper investigation." path="/soc-analyst" accent="amber" />
    </section>

    <section className="bottom-grid">
      <div className="panel system-panel">
        <div className="panel-header"><div className="panel-title-wrap"><span className="panel-icon"><Activity size={16} /></span><div><h3>System status</h3><p>LOCAL ENVIRONMENT</p></div></div><span className={`health-pill ${isHealthy ? 'healthy' : healthError ? 'error' : ''}`}><span />{isHealthy ? 'HEALTHY' : healthError ? 'OFFLINE' : 'CONNECTING'}</span></div>
        <div className="system-content">
          <div className="system-row"><span className="system-row-name"><span className="service-mark api-mark">API</span><span><strong>Backend service</strong><small>FastAPI · localhost:8000</small></span></span><span className={`system-value ${health ? (health.status === 'ok' ? 'value-ok' : 'value-error') : ''}`}>{health?.status === 'ok' ? 'Operational' : healthError ? 'Unavailable' : 'Checking'}</span></div>
          <div className="system-row"><span className="system-row-name"><span className="service-mark db-mark">DB</span><span><strong>Local database</strong><small>SQLite · workspace data</small></span></span><span className={`system-value ${health ? (health.database === 'ok' ? 'value-ok' : 'value-error') : ''}`}>{health?.database === 'ok' ? 'Connected' : healthError ? 'Unavailable' : 'Checking'}</span></div>
        </div>
        <div className="panel-footer"><span>{health ? `Last checked just now · ${health.response_time_ms} ms` : healthError ? 'Could not reach the local API' : 'Connecting to local API…'}</span><button className="text-button" type="button" onClick={onCheck} disabled={checking}>{checking ? 'Checking…' : 'Refresh status'} <ArrowRight size={13} /></button></div>
      </div>

      <div className="panel activity-panel">
        <div className="panel-header"><div className="panel-title-wrap"><span className="panel-icon activity-icon"><Gauge size={16} /></span><div><h3>Your workspace</h3><p>READY WHEN YOU ARE</p></div></div><span className="workspace-state"><span /> STANDING BY</span></div>
        <div className="workspace-summary"><div className="summary-number">{overview?.total_investigations ?? '—'}</div><div><strong>saved investigations</strong><p>{overview ? `${overview.total_reports} reports · ${overview.ctf_investigations} CTF · ${overview.bug_bounty_reports} bug bounty · ${overview.soc_investigations} SOC` : 'Metrics load from the local database.'}</p></div><ArrowDownRight size={18} className="summary-arrow" /></div>
        <Link className="panel-link" to="/history">View investigation history <ArrowRight size={14} /></Link>
      </div>
    </section>
    <div className="dashboard-lower"><CommandRouter/><section className="panel recent-panel"><div className="panel-header"><div><h3>Recent activity</h3><p>FROM YOUR LOCAL DATABASE</p></div></div>{overview?.recent_activity.length ? overview.recent_activity.map(item => <Link className="recent-row" key={item.id} to="/history"><strong>{item.title}</strong><small>{item.agent.replace('_',' ')} · {new Date(item.created_at).toLocaleString()}</small></Link>) : <p className="muted-empty">{overview ? 'No saved investigations yet. Results appear here after you save them.' : 'Could not load workspace activity.'}</p>}</section></div>
  </>
}

function ToolCard({ number, icon: Icon, title, category, description, path, accent }: { number: string; icon: LucideIcon; title: string; category: string; description: string; path: string; accent: string }) {
  return <Link to={path} className={`tool-card ${accent}`}>
    <div className="tool-card-top"><span className="tool-icon"><Icon size={19} strokeWidth={1.8} /></span><span className="tool-number">{number} <span>—</span> 03</span></div>
    <p className="tool-category">{category}</p><h3>{title}</h3><p className="tool-description">{description}</p>
    <div className="tool-card-bottom"><span>OPEN WORKSPACE <ArrowRight size={14} /></span><span className="tool-card-line" /></div>
  </Link>
}

const ctfCategories: Array<{ value: CtfCategory; label: string }> = [
  { value: 'web', label: 'Web' },
  { value: 'crypto', label: 'Cryptography' },
  { value: 'reverse', label: 'Reverse engineering' },
  { value: 'forensics', label: 'Digital forensics' },
  { value: 'pwn', label: 'Binary exploitation' },
  { value: 'misc', label: 'Miscellaneous' },
  { value: 'osint', label: 'OSINT' },
  { value: 'mobile', label: 'Mobile' },
]

function CtfAnalystPage() {
  const [challengeTitle, setChallengeTitle] = useState('')
  const [challengeDescription, setChallengeDescription] = useState('')
  const [category, setCategory] = useState<CtfCategory>('misc')
  const [difficulty, setDifficulty] = useState<CtfInput['difficulty']>('unknown')
  const [challengeArtifacts, setChallengeArtifacts] = useState('')
  const [userQuestion, setUserQuestion] = useState('')
  const [commandInput, setCommandInput] = useState('')
  const [analysis, setAnalysis] = useState<CtfAnalysis | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState<'analyze' | 'demo' | null>(null)
  const [saved, setSaved] = useState('')

  const analyze = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (!commandInput.trim()) {
      setError('Enter a command, output, or note before running analysis.')
      return
    }
    setBusy('analyze')
    setError('')
    try {
      setAnalysis(await requestCtfAnalysis({
        challenge_description: challengeDescription.trim(),
        challenge_title: challengeTitle.trim() || 'Untitled challenge',
        category,
        difficulty,
        challenge_artifacts: challengeArtifacts.trim(),
        user_question: userQuestion.trim(),
        command_input: commandInput.trim(),
      }))
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : 'The analysis request failed. Check the backend and try again.')
    } finally {
      setBusy(null)
    }
  }

  const tryDemo = async () => {
    setBusy('demo')
    setError('')
    try {
      const demo = await requestCtfDemo()
      setChallengeDescription(demo.challenge_description)
      setChallengeTitle(demo.challenge_title)
      setCategory(demo.category)
      setDifficulty(demo.difficulty)
      setChallengeArtifacts(demo.challenge_artifacts)
      setUserQuestion(demo.user_question)
      setCommandInput(demo.command_input)
      setAnalysis(demo.analysis)
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : 'The demo request failed. Check the backend and try again.')
    } finally {
      setBusy(null)
    }
  }

  const save = async () => {
    if (!analysis) return
    setBusy('analyze'); setError(''); setSaved('')
    try {
      const response = await fetch('/api/investigations', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ title: challengeTitle.trim() || 'CTF challenge', agent: 'ctf', input: { challenge_title: challengeTitle, challenge_description: challengeDescription, category, difficulty, challenge_artifacts: challengeArtifacts, user_question: userQuestion, command_input: commandInput }, result: analysis, summary: analysis.result.slice(0, 220) }) })
      const data = await response.json(); if (!response.ok) throw new Error(data.detail || `Save failed (${response.status}).`)
      setSaved(`Saved to local history (${String(data.id).slice(0, 8)}).`)
    } catch (error) { setError(error instanceof Error ? error.message : 'Could not save the investigation.') } finally { setBusy(null) }
  }

  return <div className="ctf-page">
    <div className="eyebrow"><span className="eyebrow-line" />WORKSPACE / ANALYSIS</div>
    <div className="subpage-heading ctf-heading"><div><h1>CTF Analyst<span className="title-period">.</span></h1><p>Reason through challenge clues, command output, and artifacts.</p></div><span className="subpage-tag"><TerminalSquare size={14} />CHALLENGE WORKSPACE</span></div>

    <div className="ctf-mode-note"><span className="mode-note-icon"><Sparkle size={15} /></span><span><strong>One analysis workspace. Two ways to get started.</strong><small>Configure an AI key for model-backed analysis, or use local demo mode without one.</small></span><span className="local-chip"><span /> PRIVATE INPUT</span></div>

    <div className="ctf-workspace-grid">
      <form className="ctf-input-panel" onSubmit={(event) => void analyze(event)}>
        <div className="ctf-panel-heading"><span className="ctf-section-icon"><TerminalSquare size={16} /></span><span><strong>Challenge input</strong><small>Describe the challenge and add what you have observed.</small></span></div>
        <label className="ctf-field"><span>CHALLENGE TITLE</span><input className="workspace-input" value={challengeTitle} onChange={event => setChallengeTitle(event.target.value)} maxLength={160} placeholder="Challenge name" /></label>
        <label className="ctf-field"><span>CHALLENGE DESCRIPTION <span className="field-optional">OPTIONAL</span></span>
          <textarea className="ctf-description" value={challengeDescription} onChange={(event) => setChallengeDescription(event.target.value)} maxLength={4000} placeholder="What is the challenge asking you to find? Include any prompt or context..." />
        </label>
        <label className="ctf-field category-field"><span>DIFFICULTY</span><select className="workspace-input" value={difficulty} onChange={event => setDifficulty(event.target.value as CtfInput['difficulty'])}>{['unknown','beginner','intermediate','advanced'].map(item => <option key={item} value={item}>{item[0].toUpperCase() + item.slice(1)}</option>)}</select></label>
        <label className="ctf-field"><span>CHALLENGE ARTIFACTS OR NOTES <span className="field-optional">OPTIONAL</span></span><textarea className="ctf-description" value={challengeArtifacts} onChange={event => setChallengeArtifacts(event.target.value)} maxLength={6000} placeholder="Paste artifact metadata, file details, or observations..." /></label>
        <label className="ctf-field"><span>YOUR QUESTION <span className="field-optional">OPTIONAL</span></span><input className="workspace-input" value={userQuestion} onChange={event => setUserQuestion(event.target.value)} maxLength={2000} placeholder="What should the analysis focus on?" /></label>
        <label className="ctf-field category-field"><span>CHALLENGE CATEGORY</span>
          <select value={category} onChange={(event) => setCategory(event.target.value as CtfCategory)}>
            {ctfCategories.map((item) => <option key={item.value} value={item.value}>{item.label}</option>)}
          </select>
        </label>
        <label className="ctf-field command-field"><span>COMMANDS, OUTPUT, OR NOTES <span className="field-required">REQUIRED</span></span>
          <textarea
            className="ctf-command-input"
            value={commandInput}
            onChange={(event) => setCommandInput(event.target.value)}
            maxLength={6000}
            placeholder="Type your command, terminal output, or challenge notes..."
            aria-label="Commands, output, or notes"
            required
            spellCheck={false}
          />
          <span className="character-count">{commandInput.length.toLocaleString()} / 6,000</span>
        </label>
        {error && <div className="ctf-error" role="alert"><AlertCircle size={15} /><span>{error}</span></div>}
        <div className="ctf-actions">
          <button className="analyze-button" type="submit" disabled={busy !== null || !commandInput.trim()}>
            {busy === 'analyze' ? <><LoaderCircle size={15} className="spin" /> Analyzing…</> : <><Sparkles size={15} /> Analyze Challenge</>}
          </button>
          <button className="demo-button" type="button" onClick={() => void tryDemo()} disabled={busy !== null}>
            {busy === 'demo' ? <><LoaderCircle size={14} className="spin" /> Loading…</> : <><Play size={13} /> Try Demo</>}
          </button>
        </div>
      </form>

      <section className="ctf-output-panel" aria-labelledby="ctf-output-title" aria-live="polite" aria-busy={busy === 'analyze' || busy === 'demo'}>
        <div className="ctf-panel-heading output-heading"><span className="ctf-output-icon"><Sparkles size={16} /></span><span><strong id="ctf-output-title">Analysis results</strong><small>{analysis ? 'Latest response from your analysis request.' : 'Your submitted challenge analysis will appear here.'}</small></span></div>
        {busy ? <div className="ctf-output-loading"><span className="loading-orbit"><LoaderCircle size={25} className="spin" /></span><strong>{busy === 'demo' ? 'Loading sample challenge…' : 'Analyzing your challenge…'}</strong><small>The result will appear here when the backend responds.</small></div> : analysis ? <div className="ctf-result">
          <div className={`result-label ${analysis.mode === 'ai' ? 'ai-result' : 'demo-result'}`}><span>{analysis.mode === 'ai' ? <CheckCircle2 size={13} /> : <Sparkle size={13} />}{analysis.label}</span>{analysis.model && <span className="result-model">{analysis.model}</span>}</div>
          <pre className="result-content">{analysis.result}</pre>
          {analysis.mode === 'demo' && <p className="result-disclaimer">Demo output is illustrative guidance. It does not execute commands or verify challenge artifacts.</p>}
          <div className="ctf-actions"><button className="demo-button" type="button" onClick={() => void save()}>Save Investigation</button><button className="demo-button" type="button" onClick={() => { const blob = new Blob([analysis.report_markdown || analysis.result], { type: 'text/markdown' }); const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url; a.download = 'ctf-analysis.md'; a.click(); URL.revokeObjectURL(url) }}>Export Markdown</button></div>
        </div> : <div className="ctf-output-empty"><div className="output-empty-art"><span /><TerminalSquare size={22} /></div><strong>Ready when you are.</strong><p>Enter challenge details and select <b>Analyze Challenge</b>, or load a sample with <b>Try Demo</b>.</p></div>}
        {saved && <p className="success-note">{saved} <Link to="/history">View history →</Link></p>}
      </section>
    </div>
    <div className="ctf-safety-note"><LockKeyhole size={13} /><span>Only the fields you submit are sent to the backend. With an AI key, the backend also sends that text to OpenAI. Without a key, no AI provider receives it.</span></div>
  </div>
}

function SettingsPage({ health, healthError, checking, onCheck }: { health: Health | null; healthError: boolean; checking: boolean; onCheck: () => void }) {
  const [settings, setSettings] = useState<{ provider: string; ai_configured: boolean; model: string; mode: string; version: string; database_path: string } | null>(null)
  const [clearState, setClearState] = useState('')
  const [clearError, setClearError] = useState('')
  useEffect(() => { void fetch('/api/settings').then(response => response.ok ? response.json() : Promise.reject()).then(setSettings).catch(() => setSettings(null)) }, [])
  const clearData = async () => {
    if (!window.confirm('Permanently delete all local investigations and reports? This cannot be undone.')) return
    setClearState('Clearing…'); setClearError('')
    try { const response = await fetch('/api/data', { method: 'DELETE' }); const data = await response.json(); if (!response.ok) throw new Error(data.detail || 'Could not clear local data.'); setClearState('Local investigation data and reports were cleared.') }
    catch (error) { setClearState(''); setClearError(error instanceof Error ? error.message : 'Could not clear local data.') }
  }
  return <div className="subpage settings-page">
    <div className="eyebrow"><span className="eyebrow-line" />PREFERENCES / ENVIRONMENT</div>
    <div className="subpage-heading"><div><h1>Settings<span className="title-period">.</span></h1><p>Review the local services connected to your workspace.</p></div><span className="subpage-tag"><Settings size={14} />ENVIRONMENT</span></div>
    <div className="settings-section"><div className="settings-section-heading"><div><h2>Local services</h2><p>These services run on your computer during development.</p></div><button className="outline-button" type="button" onClick={onCheck} disabled={checking}>{checking ? 'Checking…' : 'Check again'} <ArrowRight size={14} /></button></div>
      <div className="settings-service"><span className="settings-service-icon"><Activity size={17} /></span><div className="settings-service-main"><strong>CyberFlow API</strong><small>FastAPI <span>·</span> http://localhost:8000</small></div><span className={`settings-service-status ${health?.status === 'ok' ? 'good' : healthError ? 'bad' : ''}`}><span />{health?.status === 'ok' ? 'Online' : healthError ? 'Unavailable' : 'Checking'}</span></div>
      <div className="settings-service"><span className="settings-service-icon db-settings-icon"><LockKeyhole size={17} /></span><div className="settings-service-main"><strong>SQLite database</strong><small>backend/data/cyberflow.db</small></div><span className={`settings-service-status ${health?.database === 'ok' ? 'good' : healthError ? 'bad' : ''}`}><span />{health?.database === 'ok' ? 'Connected' : healthError ? 'Unavailable' : 'Checking'}</span></div>
      <div className="settings-footnote"><CircleHelp size={14} />Service status comes from a live request to your local API.</div>
    </div>
    <div className="settings-section"><div className="settings-section-heading"><div><h2>AI Configuration</h2><p>Configuration is read by the backend. Secrets are never sent to the browser.</p></div></div>
      <div className="settings-service"><span className="settings-service-icon"><Sparkles size={17}/></span><div className="settings-service-main"><strong>AI provider</strong><small>{settings?.provider ?? 'Checking'} · {settings?.mode ?? 'Loading mode'}</small></div><span className={`settings-service-status ${settings?.ai_configured ? 'good' : ''}`}><span/>{settings?.ai_configured ? 'Configured' : settings ? 'Demo mode' : 'Checking'}</span></div>
      <div className="settings-service"><span className="settings-service-icon"><TerminalSquare size={17}/></span><div className="settings-service-main"><strong>Configured model</strong><small>{settings?.model ?? 'Loading'} · Application version {settings?.version ?? '—'}</small></div><span className="settings-service-status">Backend setting</span></div>
    </div>
    <div className="settings-section danger-section"><div className="settings-section-heading"><div><h2>Local data</h2><p>Stored investigations and reports are on this device.</p></div><button className="outline-button danger-button" type="button" onClick={() => void clearData()}>Clear local data</button></div>{clearState && <p className="success-note">{clearState}</p>}{clearError && <div className="ctf-error">{clearError}</div>}</div>
  </div>
}

export default App
