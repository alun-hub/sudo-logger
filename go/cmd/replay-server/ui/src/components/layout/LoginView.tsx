import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { login } from '@/api/config'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Key, User, ShieldCheck, AlertCircle } from 'lucide-react'
import logo from '@/assets/logo-icon-72.svg'

export function LoginView() {
  const navigate = useNavigate()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [isPending, setIsPending] = useState(false)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsPending(true)
    setError(null)

    try {
      await login(username, password)
      navigate('/')
      window.location.reload() // Ensure fresh session state
    } catch (err: any) {
      setError(err.message || 'Invalid username or password')
    } finally {
      setIsPending(false)
    }
  }

  return (
    <div className="min-h-screen bg-background flex flex-col items-center justify-center p-6">
      <div className="w-full max-w-sm space-y-8">
        <div className="flex flex-col items-center space-y-4">
          <img src={logo} alt="Sudo Logger" className="w-16 h-16" />
          <div className="text-center">
            <h1 className="text-2xl font-bold text-text tracking-tight">Sudo Logger</h1>
            <p className="text-text-dim text-sm">Secure Terminal Recording & Auditing</p>
          </div>
        </div>

        <div className="bg-card border border-border rounded-lg shadow-xl p-8 space-y-6">
          <div className="flex items-center gap-2 text-blue font-semibold border-b border-border pb-4">
            <ShieldCheck size={18} />
            <span>Secure Access</span>
          </div>

          <form onSubmit={handleSubmit} className="space-y-5">
            <div className="space-y-1.5">
              <label className="text-xs font-bold text-text-dim uppercase tracking-wider">Username</label>
              <div className="relative">
                <User className="absolute left-3 top-1/2 -translate-y-1/2 text-text-dim" size={16} />
                <Input
                  autoFocus
                  required
                  value={username}
                  onChange={e => setUsername(e.target.value)}
                  placeholder="admin"
                  className="pl-10 bg-surface border-border focus:border-blue transition-colors"
                />
              </div>
            </div>

            <div className="space-y-1.5">
              <label className="text-xs font-bold text-text-dim uppercase tracking-wider">Password</label>
              <div className="relative">
                <Key className="absolute left-3 top-1/2 -translate-y-1/2 text-text-dim" size={16} />
                <Input
                  type="password"
                  required
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  placeholder="••••••••"
                  className="pl-10 bg-surface border-border focus:border-blue transition-colors"
                />
              </div>
            </div>

            {error && (
              <div className="p-3 bg-red/10 border border-red/20 rounded flex items-center gap-3 text-red text-sm animate-in fade-in zoom-in duration-200">
                <AlertCircle size={16} className="shrink-0" />
                <span>{error}</span>
              </div>
            )}

            <Button
              type="submit"
              disabled={isPending}
              className="w-full bg-blue hover:bg-blue/90 text-white font-bold h-11 rounded-md shadow-lg shadow-blue/20 transition-all active:scale-[0.98]"
            >
              {isPending ? 'Authenticating...' : 'Sign In'}
            </Button>
          </form>
        </div>
      </div>
    </div>
  )
}
