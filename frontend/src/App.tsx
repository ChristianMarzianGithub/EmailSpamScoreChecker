import axios from 'axios'
import { useEffect, useMemo, useState } from 'react'
import { clsx } from 'clsx'
import { AnalysisResponse, HistoryEntry, SpamCategory } from './types'
import { useHistory } from './hooks/useHistory'

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000'

const samples: Record<string, string> = {
  spam1: "From: winner@mailinator.com\nSubject: WIN BIG NOW!!!\n\nClaim now for free money!!! Visit http://bit.ly/spammy",
  spam2: "From: promo@unknown-domain.biz\nSubject: LIMITED OFFER\n\nCheap meds available at http://cheap-meds.example",
  spam3: "From: fakebank@secure-alert.com\nSubject: ACCOUNT LOCKED\n\nClick here to restore access: http://tinyurl.com/phish",
  spam4: "From: casino@vipgames.com\nSubject: Casino BONUS\n\nPlay now and win big!!!",
  legit: "From: support@trusted.com\nSubject: Meeting Notes\n\nHi team,\nHere are the meeting notes attached. Thanks!",
}

type Mode = 'content' | 'headers'

type ErrorState = string | null

function categoryColor(category: SpamCategory) {
  switch (category) {
    case 'SAFE':
      return 'bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-200'
    case 'SUSPICIOUS':
      return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/40 dark:text-yellow-200'
    case 'LIKELY_SPAM':
    default:
      return 'bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-200'
  }
}

const headerStatuses: Record<string, string> = {
  spf: 'SPF',
  dkim: 'DKIM',
  dmarc: 'DMARC',
}

function HeaderStatus({ headers }: { headers: AnalysisResponse['headers'] }) {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
      {Object.entries(headers).map(([key, value]) => (
        <div key={key} className="p-3 rounded border border-gray-200 dark:border-gray-700">
          <div className="text-sm text-gray-500 dark:text-gray-400">{headerStatuses[key]}</div>
          <div className={clsx('font-semibold', value === 'pass' ? 'text-green-600' : 'text-red-500')}>
            {value}
          </div>
        </div>
      ))}
    </div>
  )
}

function RuleList({ rules }: { rules: AnalysisResponse['rules_triggered'] }) {
  if (!rules.length) {
    return <p className="text-sm text-gray-500">No issues found.</p>
  }
  return (
    <ul className="space-y-2">
      {rules.map((rule) => (
        <li key={rule.name} className="p-3 bg-gray-50 dark:bg-gray-800 rounded border border-gray-200 dark:border-gray-700">
          <div className="font-semibold">{rule.name}</div>
          <div className="text-sm text-gray-600 dark:text-gray-300">+{rule.points} — {rule.info}</div>
        </li>
      ))}
    </ul>
  )
}

function HistoryList({ entries }: { entries: HistoryEntry[] }) {
  if (!entries.length) return <p className="text-sm text-gray-500">History is empty.</p>
  return (
    <ul className="space-y-2 text-sm">
      {entries.map((entry) => (
        <li key={entry.id} className="p-2 border border-gray-200 dark:border-gray-700 rounded flex justify-between">
          <span className="text-gray-600 dark:text-gray-300">{new Date(entry.timestamp).toLocaleString()}</span>
          <span className={clsx('px-2 py-1 rounded text-xs font-semibold', categoryColor(entry.category))}>
            {entry.category} ({entry.score})
          </span>
        </li>
      ))}
    </ul>
  )
}

function sampleButtons(setInput: (val: string) => void) {
  return (
    <div className="flex flex-wrap gap-2 text-sm">
      {Object.entries(samples).map(([key, val]) => (
        <button
          key={key}
          className="px-3 py-1 rounded border border-gray-200 dark:border-gray-700 hover:bg-gray-100 dark:hover:bg-gray-800"
          onClick={() => setInput(val)}
        >
          {key.toUpperCase()}
        </button>
      ))}
    </div>
  )
}

function App() {
  const [mode, setMode] = useState<Mode>('content')
  const [raw, setRaw] = useState(samples.legit)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<ErrorState>(null)
  const [result, setResult] = useState<AnalysisResponse | null>(null)
  const [theme, setTheme] = useState<'light' | 'dark'>('light')
  const { history, addEntry } = useHistory()

  useEffect(() => {
    document.documentElement.classList.toggle('dark', theme === 'dark')
  }, [theme])

  const handleAnalyze = async () => {
    setError(null)
    setResult(null)
    if (!raw.trim()) {
      setError('Input cannot be empty')
      return
    }
    if (mode === 'headers') {
      try {
        // lightweight validation
        if (!/^[\w-]+:/m.test(raw)) {
          throw new Error('Invalid header format')
        }
      } catch (err) {
        setError((err as Error).message)
        return
      }
    }
    setLoading(true)
    try {
      const response = await axios.post<AnalysisResponse>(`${API_URL}/analyze`, { raw })
      setResult(response.data)
      addEntry({
        id: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        category: response.data.category,
        score: response.data.score,
        inputType: mode,
      })
    } catch (err) {
      if (axios.isAxiosError(err) && err.response) {
        setError(err.response.data?.detail || 'Analysis failed')
      } else {
        setError('Backend timeout or unreachable')
      }
    } finally {
      setLoading(false)
    }
  }

  const categoryBadge = useMemo(() => {
    if (!result) return null
    return (
      <span className={clsx('px-2 py-1 rounded text-sm font-semibold', categoryColor(result.category))}>
        {result.category}
      </span>
    )
  }, [result])

  return (
    <div className="min-h-screen">
      <header className="border-b border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900">
        <div className="max-w-6xl mx-auto px-4 py-4 flex justify-between items-center">
          <div>
            <h1 className="text-2xl font-bold">Email Spam Score Checker</h1>
            <p className="text-sm text-gray-500">Analyze raw email content or headers for spam signals.</p>
          </div>
          <button
            onClick={() => setTheme(theme === 'light' ? 'dark' : 'light')}
            className="px-3 py-2 rounded border border-gray-200 dark:border-gray-700 hover:bg-gray-100 dark:hover:bg-gray-800"
          >
            {theme === 'light' ? 'Dark Mode' : 'Light Mode'}
          </button>
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-4 py-6 grid grid-cols-1 lg:grid-cols-3 gap-6">
        <section className="lg:col-span-2 space-y-4">
          <div className="flex items-center gap-3">
            <button
              className={clsx(
                'px-4 py-2 rounded',
                mode === 'content' ? 'bg-blue-600 text-white' : 'bg-gray-200 dark:bg-gray-800'
              )}
              onClick={() => setMode('content')}
            >
              Paste Email Content
            </button>
            <button
              className={clsx(
                'px-4 py-2 rounded',
                mode === 'headers' ? 'bg-blue-600 text-white' : 'bg-gray-200 dark:bg-gray-800'
              )}
              onClick={() => setMode('headers')}
            >
              Paste Email Headers Only
            </button>
            <div className="ml-auto">{sampleButtons(setRaw)}</div>
          </div>

          <textarea
            value={raw}
            onChange={(e) => setRaw(e.target.value)}
            rows={10}
            className="w-full p-3 rounded border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800"
            placeholder={mode === 'content' ? 'Paste full email content...' : 'Paste email headers...'}
          />

          {error && <div className="p-3 rounded bg-red-100 text-red-800 dark:bg-red-900/40">{error}</div>}

          <button
            onClick={handleAnalyze}
            disabled={loading}
            className="px-4 py-2 rounded bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-60"
          >
            {loading ? 'Checking...' : 'Check Spam Score'}
          </button>

          {result && (
            <div className="space-y-4 p-4 rounded border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800">
              <div className="flex items-center gap-3">
                <div className="text-4xl font-bold">{result.score}</div>
                {categoryBadge}
              </div>
              <HeaderStatus headers={result.headers} />
              <div>
                <h3 className="font-semibold mb-2">Triggered Rules</h3>
                <RuleList rules={result.rules_triggered} />
              </div>
              <div>
                <h3 className="font-semibold mb-2">Extracted Links</h3>
                {result.links.length ? (
                  <ul className="list-disc list-inside text-blue-600 dark:text-blue-300">
                    {result.links.map((link) => (
                      <li key={link}>
                        <a href={link} target="_blank" rel="noreferrer" className="underline">
                          {link}
                        </a>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-sm text-gray-500">No links found.</p>
                )}
              </div>
            </div>
          )}
        </section>

        <aside className="space-y-4">
          <div className="p-4 rounded border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800">
            <h3 className="font-semibold mb-2">Local History</h3>
            <HistoryList entries={history} />
          </div>
          <div className="p-4 rounded border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800">
            <h3 className="font-semibold mb-2">How scoring works</h3>
            <ul className="list-disc list-inside text-sm space-y-1 text-gray-600 dark:text-gray-300">
              <li>Spam keywords, excessive punctuation, suspicious URLs.</li>
              <li>Header checks for SPF, DKIM, DMARC failures.</li>
              <li>Disposable domains, new registrations, and DNS blocklists.</li>
              <li>HTML structure and all-caps subject detection.</li>
            </ul>
          </div>
        </aside>
      </main>
    </div>
  )
}

export default App
