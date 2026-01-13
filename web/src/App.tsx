import { BrowserRouter, Routes, Route } from 'react-router-dom'
import { Layout } from './components/Layout'
import { DashboardPage } from './pages/Dashboard'
import { ScansPage } from './pages/Scans'
import { ScanDetailPage } from './pages/ScanDetail'
import { FindingsPage } from './pages/Findings'
import { FindingDetailPage } from './pages/FindingDetail'
import { RepositoriesPage } from './pages/Repositories'
import { NewScanPage } from './pages/NewScan'
import { ComparePage } from './pages/Compare'

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index element={<DashboardPage />} />
          <Route path="scans" element={<ScansPage />} />
          <Route path="scans/:scanId" element={<ScanDetailPage />} />
          <Route path="scans/new" element={<NewScanPage />} />
          <Route path="scans/compare" element={<ComparePage />} />
          <Route path="findings" element={<FindingsPage />} />
          <Route path="findings/:findingId" element={<FindingDetailPage />} />
          <Route path="repositories" element={<RepositoriesPage />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}

export default App

