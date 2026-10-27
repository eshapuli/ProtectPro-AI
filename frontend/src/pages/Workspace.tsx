import { useState, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { 
  AlignLeft, Image as ImageIcon, Link as LinkIcon, QrCode, 
  AlertTriangle, CheckCircle2, Loader2, ArrowLeft, ShieldAlert, Fingerprint
} from 'lucide-react'
import { analysisService } from '../services/api'
import Sidebar from '../components/Sidebar'

export default function Workspace() {
  const navigate = useNavigate()
  const [activeTab, setActiveTab] = useState<'text' | 'screenshot' | 'url' | 'qr'>('text')
  const [textInput, setTextInput] = useState('')
  const [urlInput, setUrlInput] = useState('')
  const [urlContext, setUrlContext] = useState('')
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<any | null>(null)
  const [similarityData, setSimilarityData] = useState<any | null>(null)

  const fileInputRef = useRef<HTMLInputElement | null>(null)

  const tabs = [
    { id: 'text', icon: AlignLeft, label: 'Text Message' },
    { id: 'url', icon: LinkIcon, label: 'Suspicious URL' },
    { id: 'screenshot', icon: ImageIcon, label: 'Screenshot OCR' },
    { id: 'qr', icon: QrCode, label: 'QR Code' }
  ]

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0]
      if (file.size > 5 * 1024 * 1024) {
        setError('Selected file exceeds maximum allowable 5MB limit.')
        setSelectedFile(null)
        return
      }
      setSelectedFile(file)
      setError(null)
    }
  }

  const handleAnalyze = async () => {
    setError(null)
    setLoading(true)
    setResult(null)

    try {
      let res
      if (activeTab === 'text') {
        if (!textInput.trim()) {
          setError('Please provide text content to analyze.')
          setLoading(false)
          return
        }
        res = await analysisService.analyzeText(textInput)
      } else if (activeTab === 'url') {
        if (!urlInput.trim()) {
          setError('Please enter a target URL to inspect.')
          setLoading(false)
          return
        }
        res = await analysisService.analyzeUrl(urlInput, urlContext || undefined)
      } else if (activeTab === 'screenshot') {
        if (!selectedFile) {
          setError('Please select a screenshot image to process.')
          setLoading(false)
          return
        }
        res = await analysisService.analyzeScreenshot(selectedFile)
      } else if (activeTab === 'qr') {
        if (!selectedFile) {
          setError('Please upload a QR code image to decode.')
          setLoading(false)
          return
        }
        res = await analysisService.analyzeQr(selectedFile)
      }
      setResult(res)
      if (res?.analysis_id) {
        try {
          const simRes = await analysisService.getSimilarMatches(res.analysis_id)
          setSimilarityData(simRes)
        } catch {
          setSimilarityData(null)
        }
      }
    } catch (err: any) {
      if (err.response?.status === 401 || err.response?.status === 403) {
        navigate('/login')
      } else {
        setError(err.response?.data?.detail || 'Analysis request failed. Please check inputs and retry.')
      }
    } finally {
      setLoading(false)
    }
  }

  const resetForm = () => {
    setResult(null)
    setSimilarityData(null)
    setTextInput('')
    setUrlInput('')
    setUrlContext('')
    setSelectedFile(null)
    setError(null)
  }

  return (
    <div className="flex h-screen bg-navy-900">
      <Sidebar activePage="workspace" />

      {/* Main Content */}
      <main className="flex-grow flex flex-col overflow-hidden">
        <header className="px-8 py-6 border-b border-navy-700 flex justify-between items-center">
          <div>
            <h1 className="text-2xl font-bold">Investigation Workspace</h1>
            <p className="text-slate-400 text-sm mt-1">Multi-modal technical evidence extraction and risk scoring.</p>
          </div>
          {result && (
            <button onClick={resetForm} className="btn-secondary text-sm flex items-center gap-2">
              <ArrowLeft className="w-4 h-4" /> New Investigation
            </button>
          )}
        </header>

        <div className="flex-grow p-8 flex justify-center overflow-y-auto">
          <div className="w-full max-w-4xl flex flex-col space-y-6">

            {error && (
              <div className="bg-red-950 border border-red-800 text-red-200 px-4 py-3 rounded-md text-sm flex items-center gap-3">
                <AlertTriangle className="w-5 h-5 text-accent-red flex-shrink-0" />
                <span>{error}</span>
              </div>
            )}

            {!result ? (
              <>
                {/* Input Type Tabs */}
                <div className="flex border-b border-navy-700">
                  {tabs.map((tab) => {
                    const Icon = tab.icon
                    const isActive = activeTab === tab.id
                    return (
                      <button
                        key={tab.id}
                        onClick={() => {
                          setActiveTab(tab.id as any)
                          setError(null)
                        }}
                        className={`flex items-center gap-2 px-6 py-3 border-b-2 font-medium transition-colors text-sm ${
                          isActive
                            ? 'border-accent-blue text-accent-blue'
                            : 'border-transparent text-slate-400 hover:text-slate-300 hover:bg-navy-800'
                        }`}
                      >
                        <Icon className="w-4 h-4" /> {tab.label}
                      </button>
                    )
                  })}
                </div>

                {/* Tab Input Panels */}
                <div className="card flex-grow flex flex-col">
                  {activeTab === 'text' && (
                    <div className="flex-grow flex flex-col">
                      <label className="text-sm font-medium text-slate-300 mb-2">Suspicious Text Payload</label>
                      <textarea
                        value={textInput}
                        onChange={(e) => setTextInput(e.target.value)}
                        className="flex-grow min-h-[220px] bg-navy-900 border border-navy-700 rounded-md p-4 text-slate-200 focus:outline-none focus:ring-1 focus:ring-accent-blue resize-none mb-4 text-sm font-mono"
                        placeholder="Paste SMS, WhatsApp message, email body, or threat notification text..."
                      />
                    </div>
                  )}

                  {activeTab === 'url' && (
                    <div className="space-y-4">
                      <div>
                        <label className="text-sm font-medium text-slate-300 mb-1 block">Target URL</label>
                        <input
                          type="url"
                          value={urlInput}
                          onChange={(e) => setUrlInput(e.target.value)}
                          className="w-full bg-navy-900 border border-navy-700 rounded-md p-3 text-slate-200 focus:outline-none focus:ring-1 focus:ring-accent-blue text-sm font-mono"
                          placeholder="https://chase-security-verify.xyz/login"
                        />
                      </div>
                      <div>
                        <label className="text-sm font-medium text-slate-300 mb-1 block">Surrounding Message Context (Optional)</label>
                        <textarea
                          value={urlContext}
                          onChange={(e) => setUrlContext(e.target.value)}
                          className="w-full h-24 bg-navy-900 border border-navy-700 rounded-md p-3 text-slate-200 focus:outline-none focus:ring-1 focus:ring-accent-blue text-sm resize-none"
                          placeholder="Include any accompanying claim (e.g. 'Your Apple ID is blocked') to test for brand/domain mismatches..."
                        />
                      </div>
                    </div>
                  )}

                  {(activeTab === 'screenshot' || activeTab === 'qr') && (
                    <div className="space-y-4">
                      <div 
                        onClick={() => fileInputRef.current?.click()}
                        className="border-2 border-dashed border-navy-700 rounded-md p-8 text-center bg-navy-900 hover:bg-navy-800 transition-colors cursor-pointer"
                      >
                        <input 
                          type="file" 
                          ref={fileInputRef} 
                          onChange={handleFileChange} 
                          accept="image/png,image/jpeg,image/webp" 
                          className="hidden" 
                        />
                        <ImageIcon className="w-12 h-12 text-slate-500 mx-auto mb-3" />
                        <p className="font-medium text-slate-200 text-sm">
                          {selectedFile ? selectedFile.name : `Click to upload ${activeTab === 'qr' ? 'QR Code' : 'Screenshot'} image`}
                        </p>
                        <p className="text-xs text-slate-500 mt-1">PNG, JPG, or WEBP up to 5MB</p>
                      </div>
                    </div>
                  )}

                  <div className="mt-8 border-t border-navy-700 pt-4 flex flex-col sm:flex-row justify-between items-center gap-4">
                    <p className="text-xs text-slate-400">
                      <strong>Privacy Notice:</strong> Analysis is executed passively. Never submit actual credentials or recovery keys.
                    </p>
                    <button
                      onClick={handleAnalyze}
                      disabled={loading}
                      className="btn-primary flex items-center gap-2 text-sm w-full sm:w-auto justify-center"
                    >
                      {loading ? (
                        <>
                          <Loader2 className="w-4 h-4 animate-spin" /> Processing Evidence...
                        </>
                      ) : (
                        <>
                          <ShieldAlert className="w-4 h-4" /> Run Technical Analysis
                        </>
                      )}
                    </button>
                  </div>
                </div>
              </>
            ) : (
              /* Investigation Report Screen */
              <div className="space-y-6">
                {/* Header Severity Banner */}
                <div className={`card border-l-4 p-6 ${
                  result.risk_level === 'Critical' || result.risk_level === 'High'
                    ? 'border-l-accent-red bg-red-950/20 border-red-900'
                    : result.risk_level === 'Medium'
                    ? 'border-l-accent-orange bg-orange-950/20 border-orange-900'
                    : 'border-l-emerald-500 bg-emerald-950/20 border-emerald-900'
                }`}>
                  <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className={`px-2 py-0.5 rounded text-xs font-bold uppercase tracking-wider ${
                          result.risk_level === 'Critical' || result.risk_level === 'High'
                            ? 'bg-red-950 text-accent-red border border-red-800'
                            : result.risk_level === 'Medium'
                            ? 'bg-orange-950 text-accent-orange border border-orange-800'
                            : 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                        }`}>
                          {result.risk_level} Risk
                        </span>
                        <span className="text-xs text-slate-400 font-mono">Investigation #{result.analysis_id}</span>
                        {result.campaign_id && (
                          <span className="px-2 py-0.5 bg-blue-950 text-accent-blue border border-blue-800 rounded text-xs font-bold font-mono">
                            Campaign {result.campaign_id}
                          </span>
                        )}
                      </div>
                      <h2 className="text-xl font-bold mt-2 text-slate-100">
                        Evidence Assessment Score: {result.risk_score} / 100
                      </h2>
                      <p className="text-xs text-slate-400 mt-1">
                        Confidence: {(result.confidence * 100).toFixed(0)}% • Category: {result.similarity_verdict || 'NEW_PATTERN'}
                      </p>
                    </div>
                  </div>
                </div>

                {/* AI Executive Threat Brief */}
                {result.ai_investigation_report && (
                  <div className="card space-y-3">
                    <h3 className="font-bold text-slate-200 text-sm flex items-center gap-2">
                      <ShieldAlert className="w-4 h-4 text-accent-blue" /> Executive Threat Brief
                    </h3>
                    <p className="text-sm text-slate-300 leading-relaxed">
                      {result.ai_investigation_report.summary}
                    </p>
                    <p className="text-xs text-slate-400 italic">
                      {result.ai_investigation_report.disclaimer}
                    </p>
                  </div>
                )}

                {/* Verified Technical Indicators */}
                <div className="card space-y-4">
                  <h3 className="font-bold text-slate-200 text-sm">
                    Verified Technical Indicators ({result.indicators?.length || 0})
                  </h3>
                  {result.indicators && result.indicators.length > 0 ? (
                    <div className="space-y-3">
                      {result.indicators.map((ind: any, i: number) => (
                        <div key={i} className="p-3 bg-navy-900 border border-navy-700 rounded-md flex flex-col gap-1 text-sm">
                          <div className="flex justify-between items-center">
                            <span className="font-semibold text-accent-blue">{ind.indicator_type}</span>
                            <span className="text-xs font-bold text-accent-red font-mono">+{ind.weight} pts</span>
                          </div>
                          <p className="text-xs text-slate-300">{ind.evidence}</p>
                          {ind.value && (
                            <code className="text-xs bg-navy-800 text-slate-400 px-2 py-1 rounded mt-1 font-mono break-all">
                              {ind.value}
                            </code>
                          )}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="text-sm text-slate-400 py-3 flex items-center gap-2">
                      <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                      <span>No malicious indicators or coercive patterns detected.</span>
                    </div>
                  )}
                </div>

                {/* Threat Fingerprint & Historical Similarity Matching Signals */}
                <div className="card space-y-4">
                  <div className="flex justify-between items-center">
                    <div className="flex items-center gap-2">
                      <Fingerprint className="w-5 h-5 text-accent-blue" />
                      <h3 className="font-bold text-slate-200 text-sm">Threat Fingerprint & Similarity Memory</h3>
                    </div>
                    <span className="text-xs px-2.5 py-1 rounded font-mono bg-navy-900 border border-navy-700 text-slate-300">
                      Verdict: {similarityData?.verdict || result.similarity_verdict || 'NEW_PATTERN'}
                    </span>
                  </div>

                  {/* Display matching signals if matches exist */}
                  {(similarityData?.matches && similarityData.matches.length > 0) || (result.matching_signals && result.matching_signals.length > 0) ? (
                    <div className="space-y-4">
                      <div className="p-3 bg-navy-900 border border-navy-700 rounded-md text-xs text-slate-300">
                        <p>
                          Historical cluster detected across{' '}
                          <span className="text-accent-blue font-bold font-mono">
                            {similarityData?.total_historical_matches || result.similarity_matches_count || 1}
                          </span>{' '}
                          prior authorized incident(s) in your tenant records.
                          {similarityData?.highest_similarity ? ` Highest observed similarity: ${(similarityData.highest_similarity * 100).toFixed(0)}%.` : ''}
                        </p>
                      </div>

                      {/* Explaining Which Signals Matched */}
                      <div className="space-y-2">
                        <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider block">
                          Matching Signals & Correlated Evidence:
                        </span>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                          {(() => {
                            const allSignals: string[] = []
                            if (result.matching_signals && Array.isArray(result.matching_signals)) {
                              allSignals.push(...result.matching_signals)
                            }
                            if (similarityData?.matches) {
                              similarityData.matches.forEach((m: any) => {
                                if (m.matching_signals && Array.isArray(m.matching_signals)) {
                                  m.matching_signals.forEach((sig: string) => {
                                    if (!allSignals.includes(sig)) allSignals.push(sig)
                                  })
                                }
                              })
                            }
                            if (allSignals.length === 0) {
                              allSignals.push("Correlated risk indicator feature vector")
                            }
                            return allSignals.map((sig, idx) => (
                              <div key={idx} className="p-2.5 bg-navy-900 border border-navy-700 rounded flex items-center gap-2 text-xs text-slate-200">
                                <span className="w-1.5 h-1.5 rounded-full bg-accent-blue flex-shrink-0"></span>
                                <span>{sig}</span>
                              </div>
                            ))
                          })()}
                        </div>
                      </div>

                      {/* Matched Historical Records */}
                      {similarityData?.matches && similarityData.matches.length > 0 && (
                        <div className="space-y-2 pt-2 border-t border-navy-700">
                          <span className="text-xs font-semibold text-slate-300 block">Correlated Case History:</span>
                          <div className="space-y-1.5 max-h-44 overflow-y-auto pr-1">
                            {similarityData.matches.map((m: any, i: number) => (
                              <div key={i} className="p-2 bg-navy-900/70 border border-navy-700/80 rounded flex justify-between items-center text-xs">
                                <div className="flex items-center gap-2">
                                  <span className="font-mono text-slate-400">Analysis #{m.analysis_id}</span>
                                  <span className="px-1.5 py-0.5 rounded text-[10px] bg-navy-800 text-slate-300 uppercase font-mono">
                                    {m.match_level ? m.match_level.replace('_', ' ') : 'SIMILAR'}
                                  </span>
                                  <span className="text-slate-400 text-[11px] capitalize">Category: {m.scam_category || 'Phishing'}</span>
                                </div>
                                <span className="font-mono text-accent-blue font-bold">
                                  {(m.similarity_score * 100).toFixed(0)}% Match
                                </span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  ) : (
                    /* Clean Empty State when no historical matches exist */
                    <div className="p-4 bg-navy-900 border border-navy-700 rounded-md text-xs text-slate-400 flex items-center gap-2.5">
                      <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
                      <span>No historical threat collisions detected in your tenant records. Structural signature cataloged as a novel pattern.</span>
                    </div>
                  )}
                </div>

                {/* Recommended Defensive Actions */}
                {result.defensive_guidance && result.defensive_guidance.length > 0 && (
                  <div className="card space-y-3">
                    <h3 className="font-bold text-slate-200 text-sm">Recommended Defensive Guidance</h3>
                    <div className="space-y-3">
                      {result.defensive_guidance.map((g: any, i: number) => (
                        <div key={i} className="p-3 bg-navy-900 border border-navy-700 rounded-md text-xs space-y-1">
                          <span className="font-semibold text-slate-200">{g.title}</span>
                          <p className="text-slate-400">{g.recommended_mitigation}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

          </div>
        </div>
      </main>
    </div>
  )
}
