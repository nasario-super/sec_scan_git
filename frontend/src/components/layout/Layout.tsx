import { Outlet } from 'react-router-dom';
import { clsx } from 'clsx';
import { Sidebar } from './Sidebar';
import { Header } from './Header';
import { Notifications } from '../ui/Notifications';
import { useStore } from '../../stores/useStore';

export function Layout() {
  const { sidebarCollapsed } = useStore();

  return (
    <div className="min-h-screen bg-cyber-bg">
      {/* Background pattern */}
      <div className="fixed inset-0 bg-grid-pattern opacity-30 pointer-events-none" />
      
      {/* Sidebar */}
      <Sidebar />

      {/* Main content */}
      <div
        className={clsx(
          'transition-all duration-300',
          sidebarCollapsed ? 'ml-16' : 'ml-64'
        )}
      >
        <Header />
        <main className="p-6 relative">
          <Outlet />
        </main>
      </div>

      {/* Notifications */}
      <Notifications />
    </div>
  );
}
