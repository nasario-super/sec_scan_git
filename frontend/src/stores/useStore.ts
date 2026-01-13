import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import type { AuthState, Notification } from '../types';
import api from '../services/api';

interface ScanSettings {
  githubToken: string;
  defaultOrganization: string;
  analyzeHistory: boolean;
  includeArchived: boolean;
  includeForks: boolean;
}

interface AppState {
  // Auth
  auth: AuthState;
  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
  checkAuth: () => Promise<void>;

  // Scan Settings
  scanSettings: ScanSettings;
  setScanSettings: (settings: Partial<ScanSettings>) => void;

  // Notifications
  notifications: Notification[];
  addNotification: (notification: Omit<Notification, 'id'>) => void;
  removeNotification: (id: string) => void;

  // UI State
  sidebarCollapsed: boolean;
  toggleSidebar: () => void;

  // Active scan tracking
  activeScanId: string | null;
  setActiveScan: (scanId: string | null) => void;
}

export const useStore = create<AppState>()(
  persist(
    (set, get) => ({
      // Auth state
      auth: {
        isAuthenticated: false,
        user: null,
        token: null,
      },

      // Scan Settings
      scanSettings: {
        githubToken: '',
        defaultOrganization: '',
        analyzeHistory: true,
        includeArchived: false,
        includeForks: false,
      },

      setScanSettings: (settings) => {
        set((state) => ({
          scanSettings: { ...state.scanSettings, ...settings },
        }));
      },

      login: async (username: string, password: string) => {
        try {
          const response = await api.login(username, password);
          const token = response.access_token;
          api.setToken(token);

          const user = await api.getCurrentUser();

          set({
            auth: {
              isAuthenticated: true,
              user,
              token,
            },
          });

          get().addNotification({
            type: 'success',
            title: 'Login successful',
            message: `Welcome back, ${user.username}!`,
          });
        } catch (error) {
          get().addNotification({
            type: 'error',
            title: 'Login failed',
            message: error instanceof Error ? error.message : 'Unknown error',
          });
          throw error;
        }
      },

      logout: () => {
        api.setToken(null);
        set({
          auth: {
            isAuthenticated: false,
            user: null,
            token: null,
          },
        });
        get().addNotification({
          type: 'info',
          title: 'Logged out',
          message: 'You have been logged out successfully.',
        });
      },

      checkAuth: async () => {
        const { auth } = get();
        if (auth.token) {
          api.setToken(auth.token);
          try {
            const user = await api.getCurrentUser();
            set({
              auth: {
                ...auth,
                isAuthenticated: true,
                user,
              },
            });
          } catch {
            // Token invalid, logout
            get().logout();
          }
        }
      },

      // Notifications
      notifications: [],

      addNotification: (notification) => {
        const id = Math.random().toString(36).substring(2, 9);
        const newNotification = { ...notification, id };

        set((state) => ({
          notifications: [...state.notifications, newNotification],
        }));

        // Auto-remove after duration
        const duration = notification.duration ?? 5000;
        if (duration > 0) {
          setTimeout(() => {
            get().removeNotification(id);
          }, duration);
        }
      },

      removeNotification: (id) => {
        set((state) => ({
          notifications: state.notifications.filter((n) => n.id !== id),
        }));
      },

      // UI State
      sidebarCollapsed: false,
      toggleSidebar: () => {
        set((state) => ({ sidebarCollapsed: !state.sidebarCollapsed }));
      },

      // Active scan
      activeScanId: null,
      setActiveScan: (scanId) => {
        set({ activeScanId: scanId });
      },
    }),
    {
      name: 'gss-storage',
      partialize: (state) => ({
        auth: state.auth,
        sidebarCollapsed: state.sidebarCollapsed,
        scanSettings: state.scanSettings,
      }),
    }
  )
);

export default useStore;
