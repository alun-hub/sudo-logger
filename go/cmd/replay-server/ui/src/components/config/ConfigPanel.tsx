import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { SiemTab }       from './SiemTab'
import { AuthTab }       from './AuthTab'
import { UsersRolesTab } from './UsersRolesTab'
import { RetentionTab }  from './RetentionTab'
import { SandboxTab }    from './SandboxTab'
import { JitTab }        from './JitTab'

export function ConfigPanel() {
  return (
    <div className="p-6 overflow-y-auto h-[calc(100vh-3rem)]">
      <Tabs defaultValue="siem">
        <TabsList className="mb-4 flex-wrap h-auto gap-1">
          <TabsTrigger value="siem">SIEM</TabsTrigger>
          <TabsTrigger value="auth">Auth</TabsTrigger>
          <TabsTrigger value="users">Users & Roles</TabsTrigger>
          <TabsTrigger value="retention">Retention</TabsTrigger>
          <TabsTrigger value="sandbox">Sandbox</TabsTrigger>
          <TabsTrigger value="jit">JIT / Approvals</TabsTrigger>
        </TabsList>
        <TabsContent value="siem"><SiemTab /></TabsContent>
        <TabsContent value="auth"><AuthTab /></TabsContent>
        <TabsContent value="users"><UsersRolesTab /></TabsContent>
        <TabsContent value="retention"><RetentionTab /></TabsContent>
        <TabsContent value="sandbox"><SandboxTab /></TabsContent>
        <TabsContent value="jit"><JitTab /></TabsContent>
      </Tabs>
    </div>
  )
}
