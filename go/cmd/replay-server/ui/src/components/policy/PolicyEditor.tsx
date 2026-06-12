import { Routes, Route, NavLink, Navigate } from 'react-router-dom'
import { Shield, ShieldCheck, Lock, Server } from 'lucide-react'
import { cn } from '@/lib/utils'

import { RulesPanel }        from './RulesPanel'
import { OPAPolicyView }     from './OPAPolicyView'
import { AccessControlView } from './AccessControlView'
import { SudoersView }       from './SudoersView'

export function PolicyEditor() {
  return (
    <div className="flex flex-col h-[calc(100vh-44px)] bg-bg text-text-sub overflow-hidden">
      <div className="px-4 border-b border-border bg-surface shrink-0">
        <nav className="h-[44px] flex items-center gap-1">
          <SubTab to="/policy/risk"   label="Risk Rules"     icon={<Shield size={14} />} />
          <SubTab to="/policy/opa"    label="OPA JIT Policy" icon={<ShieldCheck size={14} />} />
          <SubTab to="/policy/access" label="Access Control" icon={<Lock size={14} />} />
          <SubTab to="/policy/sudoers" label="Sudoers"       icon={<Server size={14} />} />
        </nav>
      </div>

      <div className="flex-1 overflow-y-auto">
        <Routes>
          <Route path="risk"    element={<div className="p-6 animate-in fade-in duration-200"><RulesPanel /></div>} />
          <Route path="opa/*"   element={<OPAPolicyView />} />
          <Route path="access"  element={<AccessControlView />} />
          <Route path="sudoers" element={<SudoersView />} />
          <Route path=""        element={<Navigate to="/policy/risk" replace />} />
        </Routes>
      </div>
    </div>
  )
}

function SubTab({ to, label, icon }: { to: string, label: string, icon: React.ReactNode }) {
  return (
    <NavLink
      to={to}
      className={({ isActive }) => cn(
        "h-full flex items-center gap-2 px-4 text-[13px] font-medium transition-all border-b-2",
        isActive
          ? "border-green text-green bg-green/5"
          : "border-transparent text-text-dim hover:text-text-sub hover:bg-card-hover"
      )}
    >
      {icon} {label}
    </NavLink>
  )
}
