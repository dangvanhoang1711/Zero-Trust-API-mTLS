import { Routes, Route, Navigate, useLocation } from 'react-router-dom';
import Layout from './components/Layout';
import Login from './pages/Login';
import Register from './pages/Register';
import Dashboard from './pages/Dashboard';
import AbacDashboard from './pages/AbacDashboard';

export default function App() {
  const location = useLocation();
  const successMessage = location.state?.success as string | undefined;

  return (
    <Layout>
      {successMessage && (
        <div className="card">
          <div className="success">{successMessage}</div>
        </div>
      )}
      <Routes>
        <Route path="/" element={<Navigate to="/login" replace />} />
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/abac" element={<AbacDashboard />} />
      </Routes>
    </Layout>
  );
}
