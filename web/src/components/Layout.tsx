import { Outlet, Link, useLocation } from 'react-router-dom'
import { motion } from 'framer-motion'
import {
  LayoutDashboard,
  Scan,
  AlertTriangle,
  FolderGit2,
  Plus,
  GitCompare,
  Shield,
  Activity,
} from 'lucide-react'
import { cn } from '@/lib/utils'

const navigation = [
  { name: 'Dashboard', href: '/', icon: LayoutDashboard },
  { name: 'Scans', href: '/scans', icon: Scan },
  { name: 'Findings', href: '/findings', icon: AlertTriangle },
  { name: 'Repositórios', href: '/repositories', icon: FolderGit2 },
]

const actions = [
  { name: 'Novo Scan', href: '/scans/new', icon: Plus },
  { name: 'Comparar', href: '/scans/compare', icon: GitCompare },
]

export function Layout() {
  const location = useLocation()

  return (
    <div className="min-h-screen bg-slate-950 bg-grid-pattern">
      {/* Sidebar */}
      <aside className="fixed inset-y-0 left-0 z-50 w-64 bg-slate-900/80 backdrop-blur-xl border-r border-slate-800/50">
        {/* Logo */}
        <div className="flex items-center gap-3 px-6 py-5 border-b border-slate-800/50">
          <div className="relative">
            <Shield className="w-8 h-8 text-neon-green" />
            <div className="absolute inset-0 blur-md bg-neon-green/30 -z-10" />
          </div>
          <div>
            <h1 className="font-display font-bold text-lg text-white">
              Security<span className="text-neon-green">Scanner</span>
            </h1>
            <p className="text-[10px] text-slate-500 uppercase tracking-widest">
              GitHub Security
            </p>
          </div>
        </div>

        {/* Navigation */}
        <nav className="px-3 py-4">
          <p className="px-3 mb-2 text-[10px] font-semibold text-slate-500 uppercase tracking-widest">
            Navegação
          </p>
          <ul className="space-y-1">
            {navigation.map((item) => {
              const isActive = location.pathname === item.href || 
                (item.href !== '/' && location.pathname.startsWith(item.href))
              
              return (
                <li key={item.name}>
                  <Link
                    to={item.href}
                    className={cn(
                      'flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-200',
                      isActive
                        ? 'bg-neon-green/10 text-neon-green border border-neon-green/20'
                        : 'text-slate-400 hover:text-white hover:bg-slate-800/50'
                    )}
                  >
                    <item.icon className="w-4 h-4" />
                    {item.name}
                    {isActive && (
                      <motion.div
                        layoutId="nav-indicator"
                        className="ml-auto w-1.5 h-1.5 rounded-full bg-neon-green"
                      />
                    )}
                  </Link>
                </li>
              )
            })}
          </ul>

          <p className="px-3 mt-6 mb-2 text-[10px] font-semibold text-slate-500 uppercase tracking-widest">
            Ações
          </p>
          <ul className="space-y-1">
            {actions.map((item) => (
              <li key={item.name}>
                <Link
                  to={item.href}
                  className="flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium text-slate-400 hover:text-white hover:bg-slate-800/50 transition-all duration-200"
                >
                  <item.icon className="w-4 h-4" />
                  {item.name}
                </Link>
              </li>
            ))}
          </ul>
        </nav>

        {/* Status */}
        <div className="absolute bottom-0 left-0 right-0 p-4 border-t border-slate-800/50">
          <div className="flex items-center gap-2 text-xs">
            <Activity className="w-3 h-3 text-neon-green animate-pulse" />
            <span className="text-slate-400">Sistema Operacional</span>
          </div>
        </div>
      </aside>

      {/* Main content */}
      <main className="pl-64">
        <div className="min-h-screen">
          <motion.div
            key={location.pathname}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.2 }}
            className="p-6"
          >
            <Outlet />
          </motion.div>
        </div>
      </main>
    </div>
  )
}

