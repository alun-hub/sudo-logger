import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { SiemTab }       from './SiemTab'
import { AuthTab }       from './AuthTab'
import { UsersRolesTab } from './UsersRolesTab'
import { RetentionTab }  from './RetentionTab'
import { SandboxTab }    from './SandboxTab'
import { JitTab }        from './JitTab'
import { Settings, Shield, Users, Database, Box, Mail } from 'lucide-react'

export function ConfigPanel() {
  return (
    <div className="flex flex-col h-[calc(100vh-[44px])] bg-bg text-text-sub overflow-hidden">
      <Tabs defaultValue="jit" className="flex-1 flex flex-col">
        <div className="px-4 border-b border-border bg-surface shrink-0">
          <TabsList className="h-[44px] bg-transparent p-0 gap-1">
            <TabsTrigger
              value="jit"
              className="h-full rounded-none border-b-2 border-transparent data-[state=active]:border-green data-[state=active]:bg-transparent data-[state=active]:text-green px-4 text-[13px] font-medium transition-all gap-2"
            >
              <Shield size={14} /> JIT / Approvals
            </TabsTrigger>
            <TabsTrigger
              value="users"
              className="h-full rounded-none border-b-2 border-transparent data-[state=active]:border-green data-[state=active]:bg-transparent data-[state=active]:text-green px-4 text-[13px] font-medium transition-all gap-2"
            >
              <Users size={14} /> Users & Roles
            </TabsTrigger>
            <TabsTrigger
              value="siem"
              className="h-full rounded-none border-b-2 border-transparent data-[state=active]:border-green data-[state=active]:bg-transparent data-[state=active]:text-green px-4 text-[13px] font-medium transition-all gap-2"
            >
              <Mail size={14} /> SIEM Forwarding
            </TabsTrigger>
            <TabsTrigger
              value="retention"
              className="h-full rounded-none border-b-2 border-transparent data-[state=active]:border-green data-[state=active]:bg-transparent data-[state=active]:text-green px-4 text-[13px] font-medium transition-all gap-2"
            >
              <Database size={14} /> Data Retention
            </TabsTrigger>
            <TabsTrigger
              value="sandbox"
              className="h-full rounded-none border-b-2 border-transparent data-[state=active]:border-green data-[state=active]:bg-transparent data-[state=active]:text-green px-4 text-[13px] font-medium transition-all gap-2"
            >
              <Box size={14} /> Process Sandbox
            </TabsTrigger>
            <TabsTrigger
              value="auth"
              className="h-full rounded-none border-b-2 border-transparent data-[state=active]:border-green data-[state=active]:bg-transparent data-[state=active]:text-green px-4 text-[13px] font-medium transition-all gap-2"
            >
              <Settings size={14} /> System Auth
            </TabsTrigger>
          </TabsList>
        </div>

        <div className="flex-1 overflow-y-auto">
          <div className="max-w-4xl p-6 mx-auto">
            <TabsContent value="jit" className="m-0 animate-in fade-in duration-200"><JitTab /></TabsContent>
            <TabsContent value="users" className="m-0 animate-in fade-in duration-200"><UsersRolesTab /></TabsContent>
            <TabsContent value="siem" className="m-0 animate-in fade-in duration-200"><SiemTab /></TabsContent>
            <TabsContent value="retention" className="m-0 animate-in fade-in duration-200"><RetentionTab /></TabsContent>
            <TabsContent value="sandbox" className="m-0 animate-in fade-in duration-200"><SandboxTab /></TabsContent>
            <TabsContent value="auth" className="m-0 animate-in fade-in duration-200"><AuthTab /></TabsContent>
          </div>
        </div>
      </Tabs>
    </div>
  )
}
