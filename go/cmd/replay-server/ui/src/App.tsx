import { lazy, Suspense } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import { AppShell } from '@/components/layout/AppShell'
import { SessionsView } from '@/components/sessions/SessionsView'

const ReportsView   = lazy(() => import('@/components/reports/ReportsView').then(m => ({ default: m.ReportsView })))
const PolicyEditor  = lazy(() => import('@/components/policy/PolicyEditor').then(m => ({ default: m.PolicyEditor })))
const ConfigPanel   = lazy(() => import('@/components/config/ConfigPanel').then(m => ({ default: m.ConfigPanel })))
const ApprovalsView = lazy(() => import('@/components/approvals/ApprovalsView').then(m => ({ default: m.ApprovalsView })))

export default function App() {
  return (
    <AppShell>
      <Suspense fallback={<div className="p-8 text-zinc-400">Loading…</div>}>
        <Routes>
          <Route path="/"          element={<SessionsView />} />
          <Route path="/reports"   element={<ReportsView />} />
          <Route path="/policy"    element={<PolicyEditor />} />
          <Route path="/config"    element={<ConfigPanel />} />
          <Route path="/approvals" element={<ApprovalsView />} />
          <Route path="*"          element={<Navigate to="/" replace />} />
        </Routes>
      </Suspense>
    </AppShell>
  )
}
