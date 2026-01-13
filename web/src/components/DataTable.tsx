import { type ReactNode } from 'react'
import { motion } from 'framer-motion'
import { cn } from '@/lib/utils'

// eslint-disable-next-line @typescript-eslint/no-explicit-any
interface Column<T = any> {
  key: string
  header: string
  width?: string
  render?: (value: unknown, row: T) => ReactNode
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
interface DataTableProps<T = any> {
  columns: Column<T>[]
  data: T[]
  onRowClick?: (row: T) => void
  isLoading?: boolean
  emptyMessage?: string
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function DataTable<T extends Record<string, any>>({
  columns,
  data,
  onRowClick,
  isLoading = false,
  emptyMessage = 'Nenhum dado encontrado',
}: DataTableProps<T>) {
  if (isLoading) {
    return (
      <div className="card-glass overflow-hidden">
        <div className="animate-pulse">
          <div className="h-12 bg-slate-800/50" />
          {[1, 2, 3, 4, 5].map((i) => (
            <div key={i} className="h-14 border-t border-slate-800/50">
              <div className="h-full px-4 flex items-center gap-4">
                <div className="h-3 bg-slate-700 rounded w-1/4" />
                <div className="h-3 bg-slate-700 rounded w-1/3" />
                <div className="h-3 bg-slate-700 rounded w-1/6" />
              </div>
            </div>
          ))}
        </div>
      </div>
    )
  }

  if (data.length === 0) {
    return (
      <div className="card-glass p-12 text-center">
        <p className="text-slate-400">{emptyMessage}</p>
      </div>
    )
  }

  return (
    <div className="card-glass overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="table-header">
              {columns.map((column) => (
                <th
                  key={column.key}
                  className="px-4 py-3 text-left font-semibold"
                  style={{ width: column.width }}
                >
                  {column.header}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {data.map((row, index) => (
              <motion.tr
                key={index}
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ duration: 0.2, delay: index * 0.02 }}
                onClick={() => onRowClick?.(row)}
                className={cn(
                  'table-row',
                  onRowClick && 'cursor-pointer'
                )}
              >
                {columns.map((column) => (
                  <td key={column.key} className="px-4 py-3 text-sm">
                    {column.render
                      ? column.render(row[column.key], row)
                      : String(row[column.key] ?? '')}
                  </td>
                ))}
              </motion.tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

interface TableSkeletonProps {
  rows?: number
  columns?: number
}

export function TableSkeleton({ rows = 5, columns = 4 }: TableSkeletonProps) {
  return (
    <div className="card-glass overflow-hidden">
      <div className="animate-pulse">
        <div className="h-12 bg-slate-800/50" />
        {Array.from({ length: rows }).map((_, i) => (
          <div key={i} className="h-14 border-t border-slate-800/50">
            <div className="h-full px-4 flex items-center gap-4">
              {Array.from({ length: columns }).map((_, j) => (
                <div
                  key={j}
                  className="h-3 bg-slate-700 rounded"
                  style={{ width: `${Math.random() * 20 + 10}%` }}
                />
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

