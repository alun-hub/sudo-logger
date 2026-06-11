import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { fetchUsers, deleteUser, fetchRoles } from '@/api/config'
import { Button } from '@/components/ui/button'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import { Users, Shield, Plus, Trash2 } from 'lucide-react'

export function UsersRolesTab() {
  const qc = useQueryClient()
  const { data: users, isPending: p1 } = useQuery({ queryKey: ['users'], queryFn: fetchUsers })
  const { data: roles, isPending: p2 } = useQuery({ queryKey: ['roles'], queryFn: fetchRoles })

  const delUser = useMutation({
    mutationFn: deleteUser,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['users'] }),
  })

  if (p1 || p2) return <div className="text-text-dim font-mono text-[13px]">Loading users & roles…</div>

  return (
    <div className="space-y-12">
      <section className="space-y-6">
        <div className="flex items-center justify-between border-b border-border pb-2">
          <h2 className="text-[16px] font-semibold text-text flex items-center gap-2">
            <Users size={18} className="text-green" /> User Management
          </h2>
          <Button size="sm" variant="outline" className="h-8 border-border hover:bg-card-hover text-text-sub">
            <Plus size={14} className="mr-1" /> Add User
          </Button>
        </div>

        <div className="rounded-[5px] border border-border bg-card overflow-hidden">
          <Table className="text-[13px]">
            <TableHeader className="bg-surface">
              <TableRow className="hover:bg-transparent border-border">
                <TableHead className="text-text-dim h-10">Username</TableHead>
                <TableHead className="text-text-dim h-10">Assigned Role</TableHead>
                <TableHead className="w-16 h-10"></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(users ?? []).map(u => (
                <TableRow key={u.username} className="hover:bg-card-hover border-border group">
                  <TableCell className="font-mono font-bold text-blue">{u.username}</TableCell>
                  <TableCell>
                    <span className="px-2 py-0.5 rounded-[3px] bg-surface border border-border text-[11px] font-semibold uppercase">
                      {u.role}
                    </span>
                  </TableCell>
                  <TableCell>
                    <button
                      onClick={() => confirm(`Delete user ${u.username}?`) && delUser.mutate(u.username)}
                      className="p-1.5 text-text-dim hover:text-red opacity-0 group-hover:opacity-100 transition-opacity"
                    >
                      <Trash2 size={14} />
                    </button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </section>

      <section className="space-y-6">
        <div className="flex items-center justify-between border-b border-border pb-2">
          <h2 className="text-[16px] font-semibold text-text flex items-center gap-2">
            <Shield size={18} className="text-blue" /> System Roles
          </h2>
        </div>

        <div className="rounded-[5px] border border-border bg-card overflow-hidden">
          <Table className="text-[13px]">
            <TableHeader className="bg-surface">
              <TableRow className="hover:bg-transparent border-border">
                <TableHead className="text-text-dim h-10">Role Name</TableHead>
                <TableHead className="text-text-dim h-10">Permissions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(roles ?? []).map(r => (
                <TableRow key={r.name} className="hover:bg-card-hover border-border">
                  <TableCell className="font-mono font-bold text-text uppercase text-[12px]">{r.name}</TableCell>
                  <TableCell className="py-3">
                    <div className="flex flex-wrap gap-1">
                      {r.permissions.map(p => (
                        <span key={p} className="text-[11px] text-text-sub font-mono bg-surface border border-border px-1.5 rounded-[2px]">
                          {p}
                        </span>
                      ))}
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </section>
    </div>
  )
}
