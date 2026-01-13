import { X, CheckCircle, AlertCircle, AlertTriangle, Info } from 'lucide-react';
import { clsx } from 'clsx';
import { useStore } from '../../stores/useStore';
import type { Notification } from '../../types';

const icons = {
  success: CheckCircle,
  error: AlertCircle,
  warning: AlertTriangle,
  info: Info,
};

const styles = {
  success: 'border-neon-green/50 bg-neon-green/10',
  error: 'border-neon-red/50 bg-neon-red/10',
  warning: 'border-neon-yellow/50 bg-neon-yellow/10',
  info: 'border-neon-blue/50 bg-neon-blue/10',
};

const iconStyles = {
  success: 'text-neon-green',
  error: 'text-neon-red',
  warning: 'text-neon-yellow',
  info: 'text-neon-blue',
};

function NotificationItem({ notification }: { notification: Notification }) {
  const { removeNotification } = useStore();
  const Icon = icons[notification.type];

  return (
    <div
      className={clsx(
        'flex items-start gap-3 p-4 rounded-lg border backdrop-blur-sm',
        'animate-slideUp shadow-lg',
        styles[notification.type]
      )}
    >
      <Icon className={clsx('w-5 h-5 flex-shrink-0 mt-0.5', iconStyles[notification.type])} />
      <div className="flex-1 min-w-0">
        <p className="text-sm font-medium text-gray-100">{notification.title}</p>
        {notification.message && (
          <p className="mt-1 text-sm text-gray-400">{notification.message}</p>
        )}
      </div>
      <button
        onClick={() => removeNotification(notification.id)}
        className="text-gray-500 hover:text-gray-300 transition-colors"
      >
        <X className="w-4 h-4" />
      </button>
    </div>
  );
}

export function Notifications() {
  const { notifications } = useStore();

  if (notifications.length === 0) return null;

  return (
    <div className="fixed bottom-4 right-4 z-50 space-y-2 max-w-sm w-full">
      {notifications.map((notification) => (
        <NotificationItem key={notification.id} notification={notification} />
      ))}
    </div>
  );
}
