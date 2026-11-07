import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Shield, Activity, AlertTriangle, Crosshair, Terminal, Server } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import './index.css';

const API_URL = 'http://127.0.0.1:8000/api';

const App = () => {
  const [events, setEvents] = useState([]);
  const [stats, setStats] = useState({});
  const [total, setTotal] = useState(0);

  const fetchData = async () => {
    try {
      const [eventsRes, statsRes] = await Promise.all([
        axios.get(`${API_URL}/events?limit=50`),
        axios.get(`${API_URL}/stats`)
      ]);
      setEvents(eventsRes.data.events || []);
      setStats(statsRes.data.stats || {});
      setTotal(statsRes.data.total_events || 0);
    } catch (e) {
      console.error("Error fetching data", e);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 2000);
    return () => clearInterval(interval);
  }, []);

  const getBadgeClass = (severityLvl) => {
    if (severityLvl >= 4) return 'badge-critical';
    if (severityLvl === 3) return 'badge-high';
    if (severityLvl === 2) return 'badge-warning';
    return 'badge-info';
  };

  const chartData = Object.keys(stats).map(key => ({
    name: key.replace(/[^\w\s]/gi, '').trim(),
    count: stats[key]
  }));

  const COLORS = ['#ef4444', '#f97316', '#eab308', '#22d3ee'];

  return (
    <div className="dashboard-container">
      <header className="header">
        <div className="header-title">
          <Shield size={36} color="#6366f1" />
          <div>
            <h1>SecureNet SOC v4.0</h1>
            <div style={{ color: 'var(--text-muted)', fontSize: '14px', marginTop: '4px' }}>
              Next-Gen Blockchain Intrusion Detection System
            </div>
          </div>
        </div>
        <div className="live-indicator">
          <div className="pulse"></div>
          LIVE MONITORING
        </div>
      </header>

      <div className="metrics-grid">
        <div className="glass-panel metric-card">
          <div className="metric-label" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Activity size={18} /> Total Events Analyzed
          </div>
          <div className="metric-value">{total.toLocaleString()}</div>
        </div>
        <div className="glass-panel metric-card">
          <div className="metric-label" style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#ef4444' }}>
            <AlertTriangle size={18} /> Critical Threats
          </div>
          <div className="metric-value">{events.filter(e => e.severity_lvl >= 4).length}</div>
        </div>
        <div className="glass-panel metric-card">
          <div className="metric-label" style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#22d3ee' }}>
            <Server size={18} /> Blockchain Sync
          </div>
          <div className="metric-value">Active</div>
        </div>
      </div>

      <div className="content-grid">
        <div className="glass-panel">
          <h2 style={{ marginBottom: '20px', display: 'flex', alignItems: 'center', gap: '10px' }}>
            <Terminal size={20} /> Live Threat Feed
          </h2>
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Severity</th>
                  <th>Source IP</th>
                  <th>Log Detail</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {events.map(event => (
                  <tr key={event.id}>
                    <td style={{ whiteSpace: 'nowrap', color: 'var(--text-muted)' }}>
                      {event.timestamp.split(' ')[1]}
                    </td>
                    <td>
                      <span className={`badge ${getBadgeClass(event.severity_lvl)}`}>
                        {event.severity}
                      </span>
                    </td>
                    <td style={{ fontFamily: 'monospace', color: '#67e8f9' }}>
                      {event.source_ip || '—'}
                    </td>
                    <td style={{ fontSize: '14px' }}>
                      {event.log_text.length > 70 ? event.log_text.substring(0, 70) + '...' : event.log_text}
                    </td>
                    <td>
                      {event.on_chain ? '🔗 Chained' : '📄 Local'}
                    </td>
                  </tr>
                ))}
                {events.length === 0 && (
                  <tr>
                    <td colSpan="5" style={{ textAlign: 'center', padding: '30px', color: 'var(--text-muted)' }}>
                      Listening for secure traffic...
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column' }}>
          <h2 style={{ marginBottom: '20px', display: 'flex', alignItems: 'center', gap: '10px' }}>
            <Crosshair size={20} /> Threat Distribution
          </h2>
          <div style={{ flex: 1, minHeight: '300px' }}>
            {chartData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={chartData} layout="vertical" margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
                  <XAxis type="number" hide />
                  <YAxis dataKey="name" type="category" axisLine={false} tickLine={false} tick={{ fill: '#a5b4fc', fontSize: 12 }} width={100} />
                  <Tooltip 
                    cursor={{ fill: 'rgba(99, 102, 241, 0.1)' }}
                    contentStyle={{ backgroundColor: '#111827', border: '1px solid #6366f1', borderRadius: '8px', color: '#fff' }}
                  />
                  <Bar dataKey="count" radius={[0, 4, 4, 0]} barSize={20}>
                    {chartData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div style={{ display: 'flex', height: '100%', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)' }}>
                No threats detected yet
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default App;
