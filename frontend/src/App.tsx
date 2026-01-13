import { useEffect, useState } from 'react';
import { BrowserRouter, Routes, Route, Navigate, useLocation } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Layout } from './components/layout/Layout';
import { Dashboard } from './pages/Dashboard';
import { Findings } from './pages/Findings';
import { Scans } from './pages/Scans';
import { Repositories } from './pages/Repositories';
import { Login } from './pages/Login';
import { Users } from './pages/Users';
import { useStore } from './stores/useStore';
import { AuthProvider, useAuth } from './contexts/AuthContext';
import api from './services/api';

// Create a client
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 1000 * 60 * 5, // 5 minutes
      retry: 1,
    },
  },
});

import { History } from './pages/History';
import { Trends } from './pages/Trends';

// Protected Route Component
function ProtectedRoute({ children, requiredRole }: { children: React.ReactNode; requiredRole?: string }) {
  const { isAuthenticated, isLoading, user } = useAuth();
  const location = useLocation();

  if (isLoading) {
    return (
      <div className="min-h-screen bg-cyber-bg flex items-center justify-center">
        <div className="text-center">
          <div className="w-12 h-12 border-4 border-neon-blue border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
          <p className="text-gray-400">Loading...</p>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  if (requiredRole && user?.role !== requiredRole && user?.role !== 'admin') {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <p className="text-severity-critical text-lg">Access Denied</p>
          <p className="text-gray-400">You don't have permission to access this page.</p>
        </div>
      </div>
    );
  }

  return <>{children}</>;
}

// Sync token with API service
function TokenSync() {
  const { isAuthenticated } = useAuth();
  
  useEffect(() => {
    const token = localStorage.getItem('gss_access_token');
    api.setToken(isAuthenticated ? token : null);
  }, [isAuthenticated]);
  
  return null;
}

function Settings() {
  const { scanSettings, setScanSettings, addNotification } = useStore();
  const [showToken, setShowToken] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ success: boolean; message: string } | null>(null);

  const handleTestConnection = async () => {
    if (!scanSettings.githubToken) {
      addNotification({
        type: 'error',
        title: 'No Token',
        message: 'Please enter a GitHub token first',
      });
      return;
    }

    setTesting(true);
    setTestResult(null);

    try {
      const response = await fetch('https://api.github.com/user', {
        headers: {
          Authorization: `Bearer ${scanSettings.githubToken}`,
          Accept: 'application/vnd.github.v3+json',
        },
      });

      if (response.ok) {
        const user = await response.json();
        setTestResult({
          success: true,
          message: `Connected as ${user.login} (${user.name || 'No name'})`,
        });
        addNotification({
          type: 'success',
          title: 'Connection Successful',
          message: `Authenticated as ${user.login}`,
        });
      } else {
        const error = await response.json();
        setTestResult({
          success: false,
          message: error.message || 'Authentication failed',
        });
        addNotification({
          type: 'error',
          title: 'Connection Failed',
          message: error.message || 'Invalid token',
        });
      }
    } catch (error) {
      setTestResult({
        success: false,
        message: 'Network error - check your connection',
      });
    } finally {
      setTesting(false);
    }
  };

  const handleSave = () => {
    addNotification({
      type: 'success',
      title: 'Settings Saved',
      message: 'Your settings have been saved locally',
    });
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-100">Settings</h1>
        <button onClick={handleSave} className="btn-primary">
          Save Settings
        </button>
      </div>
      
      <div className="card">
        <h2 className="text-lg font-semibold text-gray-100 mb-4">GitHub Connection</h2>
        <div className="space-y-4">
          <div>
            <label className="block text-sm text-gray-400 mb-2">GitHub Token</label>
            <div className="relative">
              <input
                type={showToken ? 'text' : 'password'}
                value={scanSettings.githubToken}
                onChange={(e) => setScanSettings({ githubToken: e.target.value })}
                placeholder="ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
                className="input pr-20"
              />
              <button
                type="button"
                onClick={() => setShowToken(!showToken)}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-xs text-gray-500 hover:text-gray-300"
              >
                {showToken ? 'Hide' : 'Show'}
              </button>
            </div>
            <p className="text-xs text-gray-500 mt-1">
              Personal Access Token with <code className="text-neon-blue">repo</code> and <code className="text-neon-blue">read:org</code> scopes.
              <a 
                href="https://github.com/settings/tokens/new?scopes=repo,read:org&description=GitHub%20Security%20Scanner" 
                target="_blank" 
                rel="noopener noreferrer"
                className="ml-2 text-neon-blue hover:underline"
              >
                Create Token →
              </a>
            </p>
          </div>
          <div>
            <label className="block text-sm text-gray-400 mb-2">Default Organization</label>
            <input
              type="text"
              value={scanSettings.defaultOrganization}
              onChange={(e) => setScanSettings({ defaultOrganization: e.target.value })}
              placeholder="my-organization"
              className="input"
            />
            <p className="text-xs text-gray-500 mt-1">
              Pre-fill organization name when starting scans
            </p>
          </div>
          <div className="flex items-center gap-4">
            <button 
              onClick={handleTestConnection} 
              disabled={testing || !scanSettings.githubToken}
              className="btn-ghost disabled:opacity-50"
            >
              {testing ? 'Testing...' : 'Test Connection'}
            </button>
            {testResult && (
              <span className={testResult.success ? 'text-neon-green text-sm' : 'text-neon-red text-sm'}>
                {testResult.success ? '✓' : '✗'} {testResult.message}
              </span>
            )}
          </div>
        </div>
      </div>

      <div className="card">
        <h2 className="text-lg font-semibold text-gray-100 mb-4">Default Scan Settings</h2>
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-200">Analyze Git History</p>
              <p className="text-sm text-gray-500">Search for secrets in commit history (slower but more thorough)</p>
            </div>
            <input 
              type="checkbox" 
              className="w-5 h-5" 
              checked={scanSettings.analyzeHistory}
              onChange={(e) => setScanSettings({ analyzeHistory: e.target.checked })}
            />
          </div>
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-200">Include Archived Repositories</p>
              <p className="text-sm text-gray-500">Scan repositories marked as archived</p>
            </div>
            <input 
              type="checkbox" 
              className="w-5 h-5"
              checked={scanSettings.includeArchived}
              onChange={(e) => setScanSettings({ includeArchived: e.target.checked })}
            />
          </div>
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-200">Include Forked Repositories</p>
              <p className="text-sm text-gray-500">Scan repositories that are forks of other repos</p>
            </div>
            <input 
              type="checkbox" 
              className="w-5 h-5"
              checked={scanSettings.includeForks}
              onChange={(e) => setScanSettings({ includeForks: e.target.checked })}
            />
          </div>
        </div>
      </div>

      <div className="card border-neon-yellow/30 bg-neon-yellow/5">
        <h2 className="text-lg font-semibold text-neon-yellow mb-2">⚠️ Security Notice</h2>
        <p className="text-sm text-gray-300">
          Your GitHub token is stored <strong>locally in your browser</strong> and is never sent to our servers for storage.
          It is only used to authenticate directly with GitHub's API during scans.
          For enhanced security, consider using a GitHub App instead of a Personal Access Token.
        </p>
      </div>
    </div>
  );
}

function AppRoutes() {
  const { checkAuth } = useStore();

  useEffect(() => {
    checkAuth();
  }, [checkAuth]);

  return (
    <Routes>
      {/* Public route */}
      <Route path="/login" element={<Login />} />
      
      {/* Protected routes */}
      <Route
        path="/"
        element={
          <ProtectedRoute>
            <Layout />
          </ProtectedRoute>
        }
      >
        <Route index element={<Dashboard />} />
        <Route path="findings" element={<Findings />} />
        <Route path="scans" element={<Scans />} />
        <Route path="repositories" element={<Repositories />} />
        <Route path="history" element={<History />} />
        <Route path="trends" element={<Trends />} />
        <Route path="settings" element={<Settings />} />
        
        {/* Admin only routes */}
        <Route
          path="users"
          element={
            <ProtectedRoute requiredRole="admin">
              <Users />
            </ProtectedRoute>
          }
        />
        
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <BrowserRouter>
          <TokenSync />
          <AppRoutes />
        </BrowserRouter>
      </AuthProvider>
    </QueryClientProvider>
  );
}

export default App;
