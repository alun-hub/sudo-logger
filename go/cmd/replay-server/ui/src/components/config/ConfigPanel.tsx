import { Routes, Route, NavLink, Navigate } from 'react-router-dom'
import { SiemTab }       from './SiemTab'
import { AuthTab }       from './AuthTab'
import { UsersRolesTab } from './UsersRolesTab'
import { RetentionTab }  from './RetentionTab'
import { SandboxTab }    from './SandboxTab'
import { JitTab }        from './JitTab'
import { Settings, Shield, Users, Database, Box, Mail } from 'lucide-react'
import { cn } from '@/lib/utils'

export function ConfigPanel() {
  return (
    <div className="flex flex-col h-[calc(100vh-[44px])] bg-bg text-text-sub overflow-hidden">
      <div className="px-4 border-b border-border bg-surface shrink-0">
        <nav className="h-[44px] flex items-center gap-1">
          <SubTab to="/config/jit"       label="JIT / Approvals" icon={<Shield size={14} />} />
          <SubTab to="/config/users"     label="Users & Roles"   icon={<Users size={14} />} />
          <SubTab to="/config/siem"      label="SIEM Forwarding" icon={<Mail size={14} />} />
          <SubTab to="/config/retention" label="Data Retention"  icon={<Database size={14} />} />
          <SubTab to="/config/sandbox"   label="Process Sandbox" icon={<Box size={14} />} />
          <SubTab to="/config/auth"      label="System Auth"     icon={<Settings size={14} />} />
        </nav>
      </div>

      <div className="flex-1 overflow-y-auto">
        <div className="max-w-4xl p-6 mx-auto">
          <Routes>
            <Route path="jit"       element={<div className="animate-in fade-in duration-200"><JitTab /></div>} />
            <Route path="users"     element={<div className="animate-in fade-in duration-200"><UsersRolesTab /></div>} />
            <Route path="siem"      element={<div className="animate-in fade-in duration-200"><SiemTab /></div>} />
            <Route path="retention" element={<div className="animate-in fade-in duration-200"><RetentionTab /></div>} />
            <Route path="sandbox"   element={<div className="animate-in fade-in duration-200"><SandboxTab /></div>} />
            <Route path="auth"      element={<div className="animate-in fade-in duration-200"><AuthTab /></div>} />
            <Route path=""          element={<Navigate to="jit" replace />} />
          </Routes>
        </div>
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
          ? "border-green text-green"
          : "border-transparent text-text-dim hover:text-text-sub hover:bg-card-hover"
      )}
    >
      {icon} {label}
    </NavLink>
  )
}
