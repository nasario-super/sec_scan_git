import { useState, useEffect } from 'react';
import {
  Users as UsersIcon,
  UserPlus,
  Pencil,
  Trash2,
  Key,
  CheckCircle,
  XCircle,
  Loader2,
  X,
} from 'lucide-react';
import { clsx } from 'clsx';
import api from '../services/api';
import { useAuth } from '../contexts/AuthContext';
import { formatDistanceToNow } from 'date-fns';

interface User {
  id: string;
  username: string;
  email: string | null;
  full_name: string | null;
  role: string;
  is_active: boolean;
  last_login_at: string | null;
  created_at: string;
}

const roleColors: Record<string, string> = {
  admin: 'bg-severity-critical/20 text-severity-critical border-severity-critical/30',
  analyst: 'bg-neon-blue/20 text-neon-blue border-neon-blue/30',
  viewer: 'bg-gray-500/20 text-gray-400 border-gray-500/30',
};

const roleLabels: Record<string, string> = {
  admin: 'Administrator',
  analyst: 'Analyst',
  viewer: 'Viewer',
};

function UserModal({
  isOpen,
  onClose,
  user,
  onSave,
}: {
  isOpen: boolean;
  onClose: () => void;
  user: User | null;
  onSave: () => void;
}) {
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    full_name: '',
    password: '',
    role: 'analyst',
  });
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    if (user) {
      setFormData({
        username: user.username,
        email: user.email || '',
        full_name: user.full_name || '',
        password: '',
        role: user.role,
      });
    } else {
      setFormData({
        username: '',
        email: '',
        full_name: '',
        password: '',
        role: 'analyst',
      });
    }
    setError('');
  }, [user, isOpen]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setIsLoading(true);

    try {
      if (user) {
        await api.updateUser(user.id, {
          email: formData.email || null,
          full_name: formData.full_name || null,
          role: formData.role,
        });
      } else {
        await api.createUser({
          username: formData.username,
          email: formData.email || undefined,
          full_name: formData.full_name || undefined,
          password: formData.password,
          role: formData.role,
        });
      }
      onSave();
      onClose();
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to save user');
    } finally {
      setIsLoading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm">
      <div className="card w-full max-w-md">
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-xl font-semibold text-gray-100">
            {user ? 'Edit User' : 'Create User'}
          </h2>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-300">
            <X className="w-5 h-5" />
          </button>
        </div>

        {error && (
          <div className="mb-4 p-3 rounded-lg bg-severity-critical/10 border border-severity-critical/30 text-severity-critical text-sm">
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-2">
              Username
            </label>
            <input
              type="text"
              value={formData.username}
              onChange={(e) => setFormData({ ...formData, username: e.target.value })}
              className="input"
              disabled={!!user}
              required
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-400 mb-2">
              Email
            </label>
            <input
              type="email"
              value={formData.email}
              onChange={(e) => setFormData({ ...formData, email: e.target.value })}
              className="input"
              placeholder="optional"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-400 mb-2">
              Full Name
            </label>
            <input
              type="text"
              value={formData.full_name}
              onChange={(e) => setFormData({ ...formData, full_name: e.target.value })}
              className="input"
              placeholder="optional"
            />
          </div>

          {!user && (
            <div>
              <label className="block text-sm font-medium text-gray-400 mb-2">
                Password
              </label>
              <input
                type="password"
                value={formData.password}
                onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                className="input"
                required
                minLength={8}
              />
              <p className="text-xs text-gray-500 mt-1">Minimum 8 characters</p>
            </div>
          )}

          <div>
            <label className="block text-sm font-medium text-gray-400 mb-2">
              Role
            </label>
            <select
              value={formData.role}
              onChange={(e) => setFormData({ ...formData, role: e.target.value })}
              className="input"
            >
              <option value="viewer">Viewer - Read only access</option>
              <option value="analyst">Analyst - Can run scans and manage findings</option>
              <option value="admin">Administrator - Full access</option>
            </select>
          </div>

          <div className="flex gap-3 pt-4">
            <button
              type="button"
              onClick={onClose}
              className="btn-ghost flex-1"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isLoading}
              className="btn-primary flex-1 flex items-center justify-center gap-2"
            >
              {isLoading && <Loader2 className="w-4 h-4 animate-spin" />}
              {user ? 'Save Changes' : 'Create User'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

function ResetPasswordModal({
  isOpen,
  onClose,
  user,
  onSave,
}: {
  isOpen: boolean;
  onClose: () => void;
  user: User | null;
  onSave: () => void;
}) {
  const [password, setPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    setPassword('');
    setError('');
  }, [isOpen]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!user) return;
    setError('');
    setIsLoading(true);

    try {
      await api.resetUserPassword(user.id, password);
      onSave();
      onClose();
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to reset password');
    } finally {
      setIsLoading(false);
    }
  };

  if (!isOpen || !user) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm">
      <div className="card w-full max-w-md">
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-xl font-semibold text-gray-100">
            Reset Password
          </h2>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-300">
            <X className="w-5 h-5" />
          </button>
        </div>

        <p className="text-gray-400 mb-4">
          Set a new password for <span className="text-gray-100 font-medium">{user.username}</span>
        </p>

        {error && (
          <div className="mb-4 p-3 rounded-lg bg-severity-critical/10 border border-severity-critical/30 text-severity-critical text-sm">
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-2">
              New Password
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="input"
              required
              minLength={8}
              autoFocus
            />
            <p className="text-xs text-gray-500 mt-1">Minimum 8 characters</p>
          </div>

          <div className="flex gap-3 pt-4">
            <button
              type="button"
              onClick={onClose}
              className="btn-ghost flex-1"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isLoading || password.length < 8}
              className="btn-primary flex-1 flex items-center justify-center gap-2"
            >
              {isLoading && <Loader2 className="w-4 h-4 animate-spin" />}
              Reset Password
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

export function Users() {
  const { user: currentUser } = useAuth();
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [showInactive, setShowInactive] = useState(false);
  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [isResetModalOpen, setIsResetModalOpen] = useState(false);
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null);

  const fetchUsers = async () => {
    try {
      const response = await api.getUsers(showInactive);
      setUsers(response.users);
    } catch (error) {
      console.error('Failed to fetch users:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchUsers();
  }, [showInactive]);

  const handleDelete = async (userId: string) => {
    try {
      await api.deleteUser(userId);
      fetchUsers();
    } catch (error) {
      console.error('Failed to delete user:', error);
    }
    setDeleteConfirm(null);
  };

  const handleActivate = async (userId: string) => {
    try {
      await api.activateUser(userId);
      fetchUsers();
    } catch (error) {
      console.error('Failed to activate user:', error);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <Loader2 className="w-12 h-12 text-neon-blue animate-spin mx-auto mb-4" />
          <p className="text-gray-400">Loading users...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-100">User Management</h1>
          <p className="text-gray-500">
            {users.length} users • Manage access and permissions
          </p>
        </div>
        <button
          onClick={() => {
            setSelectedUser(null);
            setIsModalOpen(true);
          }}
          className="btn-primary flex items-center gap-2"
        >
          <UserPlus className="w-4 h-4" />
          Add User
        </button>
      </div>

      {/* Filters */}
      <div className="card">
        <label className="flex items-center gap-2 text-sm text-gray-400 cursor-pointer">
          <input
            type="checkbox"
            checked={showInactive}
            onChange={(e) => setShowInactive(e.target.checked)}
            className="w-4 h-4 rounded border-cyber-border bg-cyber-surface"
          />
          Show inactive users
        </label>
      </div>

      {/* Users table */}
      <div className="card overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-cyber-border">
              <th className="text-left py-3 px-4 text-gray-400 font-medium text-sm">User</th>
              <th className="text-left py-3 px-4 text-gray-400 font-medium text-sm">Role</th>
              <th className="text-left py-3 px-4 text-gray-400 font-medium text-sm">Status</th>
              <th className="text-left py-3 px-4 text-gray-400 font-medium text-sm">Last Login</th>
              <th className="text-right py-3 px-4 text-gray-400 font-medium text-sm">Actions</th>
            </tr>
          </thead>
          <tbody>
            {users.map((user) => (
              <tr
                key={user.id}
                className={clsx(
                  'border-b border-cyber-border/50 hover:bg-cyber-surface/50 transition-colors',
                  !user.is_active && 'opacity-50'
                )}
              >
                <td className="py-3 px-4">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-full bg-gradient-to-br from-neon-blue to-neon-purple flex items-center justify-center text-white font-medium">
                      {user.username[0].toUpperCase()}
                    </div>
                    <div>
                      <p className="font-medium text-gray-100">{user.username}</p>
                      <p className="text-sm text-gray-500">
                        {user.full_name || user.email || 'No details'}
                      </p>
                    </div>
                  </div>
                </td>
                <td className="py-3 px-4">
                  <span className={clsx(
                    'px-2 py-1 rounded-full text-xs font-medium border',
                    roleColors[user.role] || roleColors.viewer
                  )}>
                    {roleLabels[user.role] || user.role}
                  </span>
                </td>
                <td className="py-3 px-4">
                  {user.is_active ? (
                    <span className="flex items-center gap-1 text-neon-green text-sm">
                      <CheckCircle className="w-4 h-4" />
                      Active
                    </span>
                  ) : (
                    <span className="flex items-center gap-1 text-gray-500 text-sm">
                      <XCircle className="w-4 h-4" />
                      Inactive
                    </span>
                  )}
                </td>
                <td className="py-3 px-4 text-gray-400 text-sm">
                  {user.last_login_at ? (
                    formatDistanceToNow(new Date(user.last_login_at), { addSuffix: true })
                  ) : (
                    'Never'
                  )}
                </td>
                <td className="py-3 px-4">
                  <div className="flex items-center justify-end gap-2">
                    <button
                      onClick={() => {
                        setSelectedUser(user);
                        setIsModalOpen(true);
                      }}
                      className="p-2 text-gray-500 hover:text-neon-blue transition-colors"
                      title="Edit user"
                    >
                      <Pencil className="w-4 h-4" />
                    </button>
                    <button
                      onClick={() => {
                        setSelectedUser(user);
                        setIsResetModalOpen(true);
                      }}
                      className="p-2 text-gray-500 hover:text-neon-yellow transition-colors"
                      title="Reset password"
                    >
                      <Key className="w-4 h-4" />
                    </button>
                    {user.id !== currentUser?.id && (
                      user.is_active ? (
                        deleteConfirm === user.id ? (
                          <div className="flex items-center gap-1">
                            <button
                              onClick={() => handleDelete(user.id)}
                              className="px-2 py-1 text-xs bg-severity-critical text-white rounded"
                            >
                              Confirm
                            </button>
                            <button
                              onClick={() => setDeleteConfirm(null)}
                              className="px-2 py-1 text-xs bg-gray-600 text-white rounded"
                            >
                              Cancel
                            </button>
                          </div>
                        ) : (
                          <button
                            onClick={() => setDeleteConfirm(user.id)}
                            className="p-2 text-gray-500 hover:text-severity-critical transition-colors"
                            title="Deactivate user"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        )
                      ) : (
                        <button
                          onClick={() => handleActivate(user.id)}
                          className="p-2 text-gray-500 hover:text-neon-green transition-colors"
                          title="Activate user"
                        >
                          <CheckCircle className="w-4 h-4" />
                        </button>
                      )
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {users.length === 0 && (
          <div className="text-center py-12">
            <UsersIcon className="w-12 h-12 text-gray-600 mx-auto mb-4" />
            <p className="text-gray-400">No users found</p>
          </div>
        )}
      </div>

      {/* Modals */}
      <UserModal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        user={selectedUser}
        onSave={fetchUsers}
      />
      <ResetPasswordModal
        isOpen={isResetModalOpen}
        onClose={() => setIsResetModalOpen(false)}
        user={selectedUser}
        onSave={fetchUsers}
      />
    </div>
  );
}
