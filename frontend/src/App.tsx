import { Routes, Route } from 'react-router-dom'
import Landing from './pages/Landing'
import Dashboard from './pages/Dashboard'
import Workspace from './pages/Workspace'
import AuthPage from './pages/AuthPage'
import HistoryPage from './pages/HistoryPage'

function App() {
  return (
    <div className="min-h-screen bg-navy-900 flex flex-col font-sans">
      <Routes>
        <Route path="/" element={<Landing />} />
        <Route path="/login" element={<AuthPage />} />
        <Route path="/register" element={<AuthPage />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/workspace" element={<Workspace />} />
        <Route path="/history" element={<HistoryPage />} />
      </Routes>
    </div>
  )
}

export default App
