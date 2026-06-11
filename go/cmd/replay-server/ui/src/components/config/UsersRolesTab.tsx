import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { fetchUsers, deleteUser, fetchRoles } from '@/api/config'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'

export function UsersRolesTab() {
  const qc = useQueryClient()
  const { data: users } = useQuery({ queryKey: ['users'], queryFn: fetchUsers })
  const { data: roles } = useQuery({ queryKey: ['roles'], queryFn: fetchRoles })

  const delUser = useMutation({
    mutationFn: deleteUser,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['users'] }),
  })

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader><CardTitle className="text-sm">Users</CardTitle></CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Username</TableHead>
                <TableHead>Role</TableHead>
                <TableHead />
              </TableRow>
            </TableHeader>
            <TableBody>
              {(users ?? []).map(u => (
                <TableRow key={u.username}>
                  <TableCell className="font-mono text-xs">{u.username}</TableCell>
                  <TableCell className="text-xs">{u.role}</TableCell>
                  <TableCell>
                    <Button
                      size="sm"
                      variant="destructive"
                      className="h-6 text-xs"
                      onClick={() => delUser.mutate(u.username)}
                    >Delete</Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle className="text-sm">Roles</CardTitle></CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Permissions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(roles ?? []).map(r => (
                <TableRow key={r.name}>
                  <TableCell className="font-mono text-xs">{r.name}</TableCell>
                  <TableCell className="text-xs">{r.permissions.join(', ')}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  )
}
