import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Shield, Lock, Mail, AlertTriangle, ArrowRight } from 'lucide-react'
import { authService } from '../services/api'

export default function AuthPage() {
  const navigate = useNavigate()
  const [isRegister, setIsRegister] = useState(false)
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    setLoading(false)

    if (!email || !password) {
      setError('Please provide both email and password.')
      return
    }

    setLoading(true)
    try {
      if (isRegister) {
        await authService.register(email, password)
        // Automatically login after register
        await authService.login(email, password)
      } else {
        await authService.login(email, password)
      }
      navigate('/dashboard')
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Authentication failed. Please verify credentials.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-navy-900 flex flex-col justify-center items-center px-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <Link to="/" className="inline-flex items-center gap-2 mb-3">
            <Shield className="w-8 h-8 text-accent-blue" />
            <span className="text-2xl font-bold text-slate-100">ProtectPro AI</span>
          </Link>
          <p className="text-sm text-slate-400">
            {isRegister ? 'Create a secure operator account' : 'Operator Portal Authentication'}
          </p>
        </div>

        <div className="card">
          {error && (
            <div className="bg-red-950 border border-red-800 text-red-200 px-4 py-3 rounded-md text-xs flex items-center gap-2 mb-4">
              <AlertTriangle className="w-4 h-4 text-accent-red flex-shrink-0" />
              <span>{error}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Email Address</label>
              <div className="relative">
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full bg-navy-900 border border-navy-700 rounded-md p-3 pl-10 text-slate-200 focus:outline-none focus:ring-1 focus:ring-accent-blue text-sm"
                  placeholder="analyst@agency.gov"
                  required
                />
                <Mail className="w-4 h-4 text-slate-500 absolute left-3 top-3.5" />
              </div>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Password</label>
              <div className="relative">
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full bg-navy-900 border border-navy-700 rounded-md p-3 pl-10 text-slate-200 focus:outline-none focus:ring-1 focus:ring-accent-blue text-sm"
                  placeholder="••••••••••••"
                  required
                />
                <Lock className="w-4 h-4 text-slate-500 absolute left-3 top-3.5" />
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="btn-primary w-full py-3 flex items-center justify-center gap-2 text-sm mt-2"
            >
              <span>{loading ? 'Authenticating...' : isRegister ? 'Register Account' : 'Sign In'}</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </form>

          <div className="mt-6 pt-4 border-t border-navy-700 text-center">
            <button
              type="button"
              onClick={() => {
                setIsRegister(!isRegister)
                setError(null)
              }}
              className="text-xs text-accent-blue hover:underline"
            >
              {isRegister ? 'Already registered? Sign in here' : "Need an account? Register new operator profile"}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
