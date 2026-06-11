import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  fetchUsers, deleteUser, upsertUser,
  fetchRoles, createRole, updateRole, deleteRole
} from '@/api/config'
import { Button } from '@/components/ui/button'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import { Users, Shield, Plus, Trash2, Edit2 } from 'lucide-react'
import { UserModal } from './UserModal'
import { RoleModal } from './RoleModal'
import type { UserInfo, Role } from '@/types/config'

export function UsersRolesTab() {
  const qc = useQueryClient()
  const { data: users, isPending: p1 } = useQuery({ queryKey: ['users'], queryFn: fetchUsers })
  const { data: roles, isPending: p2 } = useQuery({ queryKey: ['roles'], queryFn: fetchRoles })

  const [editUser, setEditUser] = useState<UserInfo | null>(null)
  const [isAddUserOpen, setIsAddUserOpen] = useState(false)

  const [editRole, setEditRole] = useState<Role | null>(null)
  const [isAddRoleOpen, setIsAddRoleOpen] = useState(false)

  const mutUser = useMutation({
    mutationFn: upsertUser,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['users'] }),
  })
  const delUser = useMutation({
    mutationFn: deleteUser,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['users'] }),
  })

  const mutRole = useMutation({
    mutationFn: (r: Role) => {
      const existing = roles?.find(x => x.name === r.name)
      return existing ? updateRole(r.name, r) : createRole(r)
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['roles'] }),
  })
  const mutDelRole = useMutation({
    mutationFn: deleteRole,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['roles'] }),
  })

  if (p1 || p2) return <div className="text-text-dim font-mono text-[13px]">Loading users & roles…</div>

  return (
    <div className="space-y-12">
      <section className="space-y-6">
        <div className="flex items-center justify-between border-b border-border pb-2">
          <h2 className="text-[16px] font-semibold text-text flex items-center gap-2">
            <Users size={18} className="text-green" /> User Management
          </h2>
          <Button
            onClick={() => setIsAddUserOpen(true)}
            size="sm" variant="outline" className="h-8 border-border hover:bg-card-hover text-text-sub"
          >
            <Plus size={14} className="mr-1" /> Add User
          </Button>
        </div>

        <div className="rounded-[5px] border border-border bg-card overflow-hidden">
          <Table className="text-[13px]">
            <TableHeader className="bg-surface">
              <TableRow className="hover:bg-transparent border-border">
                <TableHead className="text-text-dim h-10">Username</TableHead>
                <TableHead className="text-text-dim h-10">Assigned Role</TableHead>
                <TableHead className="w-24 h-10"></TableHead>
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
                    <div className="flex justify-end gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                      <button
                        onClick={() => setEditUser(u)}
                        className="p-1.5 text-text-dim hover:text-white"
                      ><Edit2 size={14} /></button>
                      <button
                        onClick={() => confirm(`Delete user ${u.username}?`) && delUser.mutate(u.username)}
                        className="p-1.5 text-text-dim hover:text-red"
                      ><Trash2 size={14} /></button>
                    </div>
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
          <Button
            onClick={() => setIsAddRoleOpen(true)}
            size="sm" variant="outline" className="h-8 border-border hover:bg-card-hover text-text-sub"
          >
            <Plus size={14} className="mr-1" /> Add Role
          </Button>
        </div>

        <div className="rounded-[5px] border border-border bg-card overflow-hidden">
          <Table className="text-[13px]">
            <TableHeader className="bg-surface">
              <TableRow className="hover:bg-transparent border-border">
                <TableHead className="text-text-dim h-10">Role Name</TableHead>
                <TableHead className="text-text-dim h-10">Permissions</TableHead>
                <TableHead className="w-24 h-10"></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(roles ?? []).map(r => (
                <TableRow key={r.name} className="hover:bg-card-hover border-border group">
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
                  <TableCell>
                    <div className="flex justify-end gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                      <button
                         onClick={() => setEditRole(r)}
                         className="p-1.5 text-text-dim hover:text-white"
                      ><Edit2 size={14} /></button>
                      <button
                        onClick={() => confirm(`Delete role ${r.name}?`) && mutDelRole.mutate(r.name)}
                        className="p-1.5 text-text-dim hover:text-red"
                      ><Trash2 size={14} /></button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </section>

      <UserModal
        user={editUser}
        roles={roles ?? []}
        open={!!editUser}
        onClose={() => setEditUser(null)}
        onSave={mutUser.mutate}
      />
      <UserModal
        user={null}
        roles={roles ?? []}
        open={isAddUserOpen}
        onClose={() => setIsAddUserOpen(false)}
        onSave={mutUser.mutate}
      />

      <RoleModal
        role={editRole}
        open={!!editRole}
        onClose={() => setEditRole(null)}
        onSave={mutRole.mutate}
      />
      <RoleModal
        role={null}
        open={isAddRoleOpen}
        onClose={() => setIsAddRoleOpen(false)}
        onSave={mutRole.mutate}
      />
    </div>
  )
}
