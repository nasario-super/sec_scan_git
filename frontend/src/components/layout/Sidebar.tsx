import { NavLink, useNavigate } from 'react-router-dom';
import { clsx } from 'clsx';
import {
  LayoutDashboard,
  Shield,
  AlertTriangle,
  GitBranch,
  ScanLine,
  Settings,
  History,
  TrendingUp,
  ChevronLeft,
  ChevronRight,
  Users,
  LogOut,
  ShieldAlert,
} from 'lucide-react';
import { useStore } from '../../stores/useStore';
import { useAuth } from '../../contexts/AuthContext';

const navigation = [
  { name: 'Dashboard', href: '/', icon: LayoutDashboard },
  { name: 'Findings', href: '/findings', icon: AlertTriangle },
  { name: 'Scans', href: '/scans', icon: ScanLine },
  { name: 'Repositories', href: '/repositories', icon: GitBranch },
  { name: 'Security Alerts', href: '/security-alerts', icon: ShieldAlert },
  { name: 'History', href: '/history', icon: History },
  { name: 'Trends', href: '/trends', icon: TrendingUp },
];

const adminNavigation = [
  { name: 'Users', href: '/users', icon: Users },
];

const secondaryNavigation = [
  { name: 'Settings', href: '/settings', icon: Settings },
];

export function Sidebar() {
  const { sidebarCollapsed, toggleSidebar } = useStore();
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <aside
      className={clsx(
        'fixed left-0 top-0 h-full bg-cyber-surface border-r border-cyber-border z-40',
        'flex flex-col transition-all duration-300',
        sidebarCollapsed ? 'w-16' : 'w-64'
      )}
    >
      {/* Logo */}
      <div className="h-16 flex items-center justify-between px-4 border-b border-cyber-border">
        {!sidebarCollapsed && (
          <div className="flex items-center gap-2">
            <Shield className="w-8 h-8 text-neon-blue" />
            <span className="font-display font-bold text-lg gradient-text">
              GSS
            </span>
          </div>
        )}
        {sidebarCollapsed && (
          <Shield className="w-8 h-8 text-neon-blue mx-auto" />
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 py-4 px-2 space-y-1 overflow-y-auto">
        {navigation.map((item) => (
          <NavLink
            key={item.name}
            to={item.href}
            className={({ isActive }) =>
              clsx(
                'nav-link',
                isActive && 'active',
                sidebarCollapsed && 'justify-center px-2'
              )
            }
            title={sidebarCollapsed ? item.name : undefined}
          >
            <item.icon className="w-5 h-5 flex-shrink-0" />
            {!sidebarCollapsed && <span>{item.name}</span>}
          </NavLink>
        ))}
        
        {/* Admin Navigation */}
        {user?.role === 'admin' && (
          <>
            {!sidebarCollapsed && (
              <div className="pt-4 pb-2">
                <p className="px-3 text-xs font-semibold text-gray-500 uppercase tracking-wider">
                  Admin
                </p>
              </div>
            )}
            {adminNavigation.map((item) => (
              <NavLink
                key={item.name}
                to={item.href}
                className={({ isActive }) =>
                  clsx(
                    'nav-link',
                    isActive && 'active',
                    sidebarCollapsed && 'justify-center px-2'
                  )
                }
                title={sidebarCollapsed ? item.name : undefined}
              >
                <item.icon className="w-5 h-5 flex-shrink-0" />
                {!sidebarCollapsed && <span>{item.name}</span>}
              </NavLink>
            ))}
          </>
        )}
      </nav>

      {/* Secondary Navigation */}
      <div className="py-4 px-2 border-t border-cyber-border space-y-1">
        {secondaryNavigation.map((item) => (
          <NavLink
            key={item.name}
            to={item.href}
            className={({ isActive }) =>
              clsx(
                'nav-link',
                isActive && 'active',
                sidebarCollapsed && 'justify-center px-2'
              )
            }
            title={sidebarCollapsed ? item.name : undefined}
          >
            <item.icon className="w-5 h-5 flex-shrink-0" />
            {!sidebarCollapsed && <span>{item.name}</span>}
          </NavLink>
        ))}
      </div>

      {/* User Info & Logout */}
      <div className="py-3 px-2 border-t border-cyber-border">
        {!sidebarCollapsed && user && (
          <div className="px-3 py-2 mb-2">
            <p className="text-sm font-medium text-gray-200 truncate">{user.username}</p>
            <p className="text-xs text-gray-500 capitalize">{user.role}</p>
          </div>
        )}
        <button
          onClick={handleLogout}
          className={clsx(
            'nav-link w-full text-gray-400 hover:text-severity-critical hover:bg-severity-critical/10',
            sidebarCollapsed && 'justify-center px-2'
          )}
          title={sidebarCollapsed ? 'Logout' : undefined}
        >
          <LogOut className="w-5 h-5 flex-shrink-0" />
          {!sidebarCollapsed && <span>Logout</span>}
        </button>
      </div>

      {/* Collapse Button */}
      <button
        onClick={toggleSidebar}
        className="h-12 flex items-center justify-center border-t border-cyber-border
                   text-gray-500 hover:text-gray-300 hover:bg-cyber-hover transition-colors"
      >
        {sidebarCollapsed ? (
          <ChevronRight className="w-5 h-5" />
        ) : (
          <ChevronLeft className="w-5 h-5" />
        )}
      </button>
    </aside>
  );
}
