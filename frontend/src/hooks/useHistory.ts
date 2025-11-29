import { useEffect, useState } from 'react'
import { HistoryEntry } from '../types'

const STORAGE_KEY = 'spam-checker-history'

export function useHistory() {
  const [history, setHistory] = useState<HistoryEntry[]>([])

  useEffect(() => {
    const stored = localStorage.getItem(STORAGE_KEY)
    if (stored) {
      try {
        setHistory(JSON.parse(stored))
      } catch (err) {
        console.error('Failed to parse history', err)
      }
    }
  }, [])

  const addEntry = (entry: HistoryEntry) => {
    const updated = [entry, ...history].slice(0, 20)
    setHistory(updated)
    localStorage.setItem(STORAGE_KEY, JSON.stringify(updated))
  }

  return { history, addEntry }
}
