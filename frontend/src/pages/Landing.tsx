import { Link } from 'react-router-dom'
import { Shield, Activity, Fingerprint } from 'lucide-react'

export default function Landing() {
  return (
    <div className="flex flex-col min-h-screen">
      <header className="px-8 py-6 flex justify-between items-center border-b border-navy-700">
        <div className="flex items-center gap-2">
          <Shield className="w-8 h-8 text-accent-blue" />
          <span className="text-xl font-bold text-slate-100">ProtectPro AI</span>
        </div>
        <nav className="flex items-center gap-4">
          <Link to="/login" className="btn-secondary text-sm">Operator Sign In</Link>
          <Link to="/workspace" className="btn-primary text-sm">Launch Workspace</Link>
        </nav>
      </header>

      <main className="flex-grow flex flex-col items-center justify-center px-4 text-center max-w-4xl mx-auto py-12">
        <div className="inline-flex items-center gap-2 px-3 py-1 bg-navy-800 border border-navy-700 rounded-full text-xs text-accent-blue font-mono mb-6">
          Defense Intelligence & Threat Analysis Platform
        </div>
        <h1 className="text-4xl md:text-6xl font-bold mb-6 text-slate-100">
          Detect the signals behind <br />
          <span className="text-accent-blue">suspicious digital communications.</span>
        </h1>
        <p className="text-lg text-slate-300 mb-10 max-w-2xl leading-relaxed">
          ProtectPro AI combines deterministic heuristic rules, multi-modal entity extraction, 
          structural fingerprinting, and threat intelligence to analyze suspicious messages, 
          lookalike domains, and QR codes without relying on generative guesses.
        </p>
        
        <div className="flex gap-4 mb-16">
          <Link to="/workspace" className="btn-primary text-lg px-8 py-3">Start an Analysis</Link>
          <Link to="/dashboard" className="btn-secondary text-lg px-8 py-3">Explore the Platform</Link>
        </div>

        <div className="grid md:grid-cols-3 gap-8 text-left w-full">
          <div className="card">
            <Activity className="w-8 h-8 text-accent-red mb-4" />
            <h3 className="text-lg font-bold mb-2">Evidence-Based Risk</h3>
            <p className="text-sm text-slate-400">Score threats using deterministic technical indicators, not hallucinations.</p>
          </div>
          <div className="card">
            <Fingerprint className="w-8 h-8 text-accent-orange mb-4" />
            <h3 className="text-lg font-bold mb-2">Scam Fingerprinting</h3>
            <p className="text-sm text-slate-400">Identify known campaigns using vector similarity search and clustering.</p>
          </div>
          <div className="card">
            <Shield className="w-8 h-8 text-accent-blue mb-4" />
            <h3 className="text-lg font-bold mb-2">Multimodal Analysis</h3>
            <p className="text-sm text-slate-400">Process text, screenshots, URLs, and QR codes securely.</p>
          </div>
        </div>
      </main>

      <footer className="py-6 border-t border-navy-700 text-center text-sm text-slate-400 mt-auto">
        &copy; {new Date().getFullYear()} ProtectPro AI. Secure intelligence platform.
      </footer>
    </div>
  )
}
