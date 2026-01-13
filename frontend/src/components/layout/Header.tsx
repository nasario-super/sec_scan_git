import { useState } from 'react';
import { useLocation } from 'react-router-dom';
import {
  Bell,
  Search,
  User,
  LogOut,
  Moon,
  Settings,
  Zap,
} from 'lucide-react';
import { useStore } from '../../stores/useStore';

const pageTitles: Record<string, string> = {
  '/': 'Dashboard',
  '/findings': 'Security Findings',
  '/scans': 'Scan History',
  '/repositories': 'Repositories',
  '/history': 'Activity History',
  '/trends': 'Security Trends',
  '/settings': 'Settings',
};

export function Header() {
  const location = useLocation();
  const { auth, logout } = useStore();
  const [showUserMenu, setShowUserMenu] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');

  const pageTitle = pageTitles[location.pathname] || 'GitHub Security Scanner';

  return (
    <header className="h-16 bg-cyber-surface/80 backdrop-blur-md border-b border-cyber-border sticky top-0 z-30">
      <div className="h-full flex items-center justify-between px-6">
        {/* Page Title */}
        <div className="flex items-center gap-3">
          <h1 className="text-xl font-semibold text-gray-100">{pageTitle}</h1>
          <div className="hidden md:flex items-center gap-2 text-xs text-gray-500">
            <span className="pulse-dot text-neon-green" />
            <span>System Online</span>
          </div>
        </div>

        {/* Search */}
        <div className="flex-1 max-w-md mx-8 hidden lg:block">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
            <input
              type="text"
              placeholder="Search findings, repositories..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="input pl-10 py-2 text-sm"
            />
            {searchQuery && (
              <kbd className="absolute right-3 top-1/2 -translate-y-1/2 px-2 py-0.5 text-xs 
                            text-gray-500 bg-cyber-bg rounded border border-cyber-border">
                Enter
              </kbd>
            )}
          </div>
        </div>

        {/* Right side actions */}
        <div className="flex items-center gap-2">
          {/* Quick scan button */}
          <button className="btn-primary flex items-center gap-2 text-sm">
            <Zap className="w-4 h-4" />
            <span className="hidden md:inline">Quick Scan</span>
          </button>

          {/* Notifications */}
          <button className="relative p-2 text-gray-400 hover:text-gray-200 
                           hover:bg-cyber-hover rounded-lg transition-colors">
            <Bell className="w-5 h-5" />
            <span className="absolute top-1 right-1 w-2 h-2 bg-neon-red rounded-full" />
          </button>

          {/* Theme toggle */}
          <button className="p-2 text-gray-400 hover:text-gray-200 
                           hover:bg-cyber-hover rounded-lg transition-colors">
            <Moon className="w-5 h-5" />
          </button>

          {/* User menu */}
          <div className="relative">
            <button
              onClick={() => setShowUserMenu(!showUserMenu)}
              className="flex items-center gap-2 p-2 text-gray-400 hover:text-gray-200 
                       hover:bg-cyber-hover rounded-lg transition-colors"
            >
              <div className="w-8 h-8 rounded-full bg-gradient-to-br from-neon-blue to-neon-purple 
                            flex items-center justify-center">
                <User className="w-4 h-4 text-white" />
              </div>
              {auth.user && (
                <span className="hidden md:inline text-sm">{auth.user.username}</span>
              )}
            </button>

            {/* Dropdown */}
            {showUserMenu && (
              <div className="absolute right-0 mt-2 w-48 py-2 bg-cyber-card border border-cyber-border 
                            rounded-lg shadow-xl animate-slideDown">
                <div className="px-4 py-2 border-b border-cyber-border">
                  <p className="text-sm font-medium text-gray-200">
                    {auth.user?.username || 'Guest'}
                  </p>
                  <p className="text-xs text-gray-500 capitalize">
                    {auth.user?.role || 'No role'}
                  </p>
                </div>
                <button
                  className="w-full px-4 py-2 text-left text-sm text-gray-400 
                           hover:text-gray-200 hover:bg-cyber-hover flex items-center gap-2"
                >
                  <Settings className="w-4 h-4" />
                  Settings
                </button>
                <button
                  onClick={() => {
                    logout();
                    setShowUserMenu(false);
                  }}
                  className="w-full px-4 py-2 text-left text-sm text-neon-red 
                           hover:bg-neon-red/10 flex items-center gap-2"
                >
                  <LogOut className="w-4 h-4" />
                  Logout
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
    </header>
  );
}
