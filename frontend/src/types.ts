export type SpamCategory = 'SAFE' | 'SUSPICIOUS' | 'LIKELY_SPAM'

export interface RuleResult {
  name: string
  points: number
  info: string
}

export interface AnalysisResponse {
  score: number
  category: SpamCategory
  rules_triggered: RuleResult[]
  links: string[]
  headers: {
    spf: string
    dkim: string
    dmarc: string
  }
}

export interface HistoryEntry {
  id: string
  timestamp: string
  category: SpamCategory
  score: number
  inputType: 'content' | 'headers'
}
