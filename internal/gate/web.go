package gate

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/Syntheticlight/2cfa-mcp/internal/updater"
)

// Handler handles /gate dashboard and API requests.
type Handler struct {
	manager   *Manager
	authToken string
}

// NewHandler creates a new Gate Web Handler.
func NewHandler(manager *Manager, authToken string) *Handler {
	return &Handler{
		manager:   manager,
		authToken: authToken,
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// The dashboard commonly authenticates via a token in the URL. Prevent
	// browsers from caching the page or leaking that URL as a referrer.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:")

	// Simple auth check for /gate dashboard: query param ?token= or Authorization header
	token := r.URL.Query().Get("token")
	if token == "" {
		authH := r.Header.Get("Authorization")
		if len(authH) > 7 && strings.EqualFold(authH[:7], "bearer ") {
			token = strings.TrimSpace(authH[7:])
		}
	}

	// Verify token
	if h.authToken == "" || subtle.ConstantTimeCompare([]byte(token), []byte(h.authToken)) != 1 {
		if strings.HasPrefix(r.URL.Path, "/gate/api/") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"unauthorized: invalid or missing token"}`))
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`<!DOCTYPE html><html><head><title>2cfa-mcp 2FA Gate</title></head><body style="background:#0d1117;color:#c9d1d9;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;"><div style="background:#161b22;padding:32px;border-radius:12px;border:1px solid #30363d;text-align:center;box-shadow:0 8px 24px rgba(0,0,0,0.5);max-width:400px;"><h2 style="color:#f85149;margin-top:0;">🔒 Access Restricted</h2><p style="color:#8b949e;line-height:1.5;">Please append your authentication token in the URL query string:</p><p><code style="background:#0d1117;padding:6px 12px;border-radius:6px;border:1px solid #30363d;color:#58a6ff;">/gate?token=YOUR_AUTH_TOKEN</code></p></div></body></html>`))
		return
	}

	switch r.URL.Path {
	case "/gate/api/status":
		h.handleStatus(w, r)
	case "/gate/api/unlock":
		h.handleUnlock(w, r)
	case "/gate/api/lock":
		h.handleLock(w, r)
	default:
		h.handleDashboard(w, r)
	}
}

func (h *Handler) handleStatus(w http.ResponseWriter, r *http.Request) {
	state := h.manager.GetState()
	audits := h.manager.GetAudits()
	upInfo := updater.GetInfo()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"state":  state,
		"audits": audits,
		"update": upInfo,
	})
}

func (h *Handler) handleUnlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}

	ip, country := ResolveClientIP(r)

	leaseToken, err := h.manager.UnlockForClient(req.Code, ip, country)
	if err != nil {
		h.manager.AddAudit(AuditEntry{
			ClientIP: ip,
			Country:  country,
			ToolName: "2fa_unlock",
			Status:   "ERROR",
			Message:  err.Error(),
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": err.Error()})
		return
	}

	h.manager.AddAudit(AuditEntry{
		ClientIP: ip,
		Country:  country,
		ToolName: "2fa_unlock",
		Status:   "SUCCESS",
		Message:  "Gate unlocked via TOTP",
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":      "ok",
		"message":     "Gate unlocked successfully",
		"lease_token": leaseToken,
	})
}

func (h *Handler) handleLock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ip, country := ResolveClientIP(r)
	h.manager.Lock()

	h.manager.AddAudit(AuditEntry{
		ClientIP: ip,
		Country:  country,
		ToolName: "emergency_lock",
		Status:   "SUCCESS",
		Message:  "Gate manually locked by operator",
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "message": "Gate locked"})
}

func (h *Handler) handleDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(dashboardHTML))
}

const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>2cfa-mcp 2FA Security Gate</title>
  <style>
    :root {
      --bg: #0d1117;
      --card-bg: #161b22;
      --border: #30363d;
      --text: #c9d1d9;
      --text-muted: #8b949e;
      --accent: #58a6ff;
      --success: #238636;
      --success-glow: rgba(35, 134, 54, 0.4);
      --danger: #da3633;
      --danger-glow: rgba(218, 54, 51, 0.4);
      --warning: #d29922;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      padding: 20px;
      background-color: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
      line-height: 1.5;
    }
    .container {
      max-width: 900px;
      margin: 0 auto;
    }
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-bottom: 20px;
      border-bottom: 1px solid var(--border);
      margin-bottom: 24px;
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .brand h1 {
      margin: 0;
      font-size: 20px;
      font-weight: 600;
      letter-spacing: 0.5px;
    }
    .brand span {
      background: #21262d;
      color: var(--accent);
      padding: 2px 8px;
      border-radius: 12px;
      font-size: 12px;
      font-family: monospace;
    }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 24px;
      margin-bottom: 24px;
      box-shadow: 0 4px 16px rgba(0,0,0,0.3);
    }
    .status-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 16px;
    }
    .status-pill {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 6px 14px;
      border-radius: 20px;
      font-weight: 600;
      font-size: 14px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .status-pill.unlocked {
      background: var(--success);
      color: #fff;
      box-shadow: 0 0 12px var(--success-glow);
    }
    .status-pill.locked {
      background: var(--danger);
      color: #fff;
      box-shadow: 0 0 12px var(--danger-glow);
    }
    .status-pill.disabled {
      background: #30363d;
      color: #8b949e;
    }
    .timer-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 16px;
      margin-top: 20px;
    }
    @media (max-width: 600px) {
      .timer-grid { grid-template-columns: 1fr; }
    }
    .timer-box {
      background: #0d1117;
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 16px;
      text-align: center;
    }
    .timer-label {
      font-size: 12px;
      color: var(--text-muted);
      text-transform: uppercase;
      margin-bottom: 6px;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 4px;
    }
    .timer-val {
      font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
      font-size: 24px;
      font-weight: 700;
      color: #58a6ff;
    }
    .actions-grid {
      display: flex;
      gap: 12px;
      margin-top: 20px;
      flex-wrap: wrap;
    }
    .input-code {
      flex: 1;
      min-width: 180px;
      background: #0d1117;
      border: 1px solid var(--border);
      color: #fff;
      padding: 10px 14px;
      border-radius: 6px;
      font-size: 16px;
      letter-spacing: 2px;
      font-family: monospace;
      outline: none;
    }
    .input-code:focus {
      border-color: var(--accent);
    }
    button {
      padding: 10px 18px;
      border-radius: 6px;
      font-size: 14px;
      font-weight: 600;
      cursor: pointer;
      border: 1px solid transparent;
      transition: all 0.2s;
    }
    .btn-primary {
      background: var(--success);
      color: #fff;
    }
    .btn-primary:hover { background: #2ea043; }
    .btn-danger {
      background: #21262d;
      color: #f85149;
      border-color: var(--border);
    }
    .btn-danger:hover {
      background: var(--danger);
      color: #fff;
    }
    .table-wrapper {
      overflow-x: auto;
      margin-top: 12px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
      text-align: left;
    }
    th, td {
      padding: 10px 12px;
      border-bottom: 1px solid var(--border);
    }
    th {
      color: var(--text-muted);
      font-weight: 600;
      text-transform: uppercase;
      font-size: 11px;
    }
    .badge {
      display: inline-block;
      padding: 2px 6px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 600;
      font-family: monospace;
    }
    .badge-success { background: rgba(35, 134, 54, 0.2); color: #3fb950; border: 1px solid rgba(35, 134, 54, 0.4); }
    .badge-error { background: rgba(218, 54, 51, 0.2); color: #f85149; border: 1px solid rgba(218, 54, 51, 0.4); }
    .badge-locked { background: rgba(210, 153, 34, 0.2); color: #d29922; border: 1px solid rgba(210, 153, 34, 0.4); }
    .country-tag {
      background: #21262d;
      color: var(--text-muted);
      padding: 1px 4px;
      border-radius: 3px;
      font-size: 10px;
      margin-left: 4px;
    }
    #msgAlert {
      margin-top: 12px;
      padding: 8px 12px;
      border-radius: 6px;
      font-size: 13px;
      display: none;
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="brand">
        <svg height="22" viewBox="0 0 24 24" width="22" fill="#58a6ff"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/></svg>
        <h1>2cfa-mcp 2FA Gate</h1>
        <span>v1.0.12</span>
      </div>
      <div id="statusBadge" class="status-pill locked">Checking...</div>
    </header>

    <div class="card">
      <h3 style="margin-top:0;">2FA Security Gate & Dynamic Leases</h3>
      <div class="timer-grid">
        <div class="timer-box">
          <div class="timer-label">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
            Gate Physical Status
          </div>
          <div class="timer-val" id="idleCountdown">CHECKING</div>
          <small style="color:var(--text-muted);font-size:11px;">Toggle dynamically in chat via setup_2fa</small>
        </div>
        <div class="timer-box">
          <div class="timer-label">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
            Active Lease Passes
          </div>
          <div class="timer-val" id="maxCountdown">0 ACTIVE</div>
          <small style="color:var(--text-muted);font-size:11px;">Dynamic implicit lease tokens minted</small>
        </div>
      </div>

      <div class="actions-grid">
        <button class="btn-danger" onclick="lockGate()">Immediate Emergency Lock</button>
      </div>
      <div id="msgAlert"></div>
    </div>

    <div class="card">
      <h3 style="margin-top:0;display:flex;justify-content:space-between;align-items:center;">
        <span>Recent Audit Logs</span>
        <small style="color:var(--text-muted);font-size:12px;font-weight:normal;">Real-time Cloudflare IP & Geo Tracking</small>
      </h3>
      <div class="table-wrapper">
        <table>
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Tool</th>
              <th>Client IP</th>
              <th>Duration</th>
              <th>Status</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody id="auditRows">
            <tr><td colspan="6" style="text-align:center;color:var(--text-muted);">Loading audit history...</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <script>
    const urlParams = new URLSearchParams(window.location.search);
    const token = urlParams.get('token') || '';

    function escapeHTML(value) {
      return String(value ?? '').replace(/[&<>"']/g, (ch) => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
      }[ch]));
    }

    async function fetchStatus() {
      try {
        const res = await fetch('/gate/api/status?token=' + encodeURIComponent(token));
        if (!res.ok) return;
        const data = await res.json();
        renderState(data.state, data.update);
        renderAudits(data.audits);
      } catch (e) {
        console.error("fetch status error:", e);
      }
    }

    function renderState(state, update) {
      if (update && update.has_update) {
        const b = document.getElementById('updateBanner');
        if (b) {
          b.style.display = 'block';
          document.getElementById('updateText').innerText = 'New ' + update.latest_version + ' available!';
          document.getElementById('updateLink').href = update.release_url;
        }
      }
      const badge = document.getElementById('statusBadge');
      const gateBox = document.getElementById('idleCountdown');
      const leasesBox = document.getElementById('maxCountdown');

      if (!state.enabled) {
        badge.className = 'status-pill disabled';
        badge.innerText = 'Gate Disabled';
        gateBox.innerText = 'DISABLED';
        leasesBox.innerText = '100% UNRESTRICTED';
        return;
      }

      const isUnlocked = state.status === 'UNLOCKED' || state.unlocked;
      if (isUnlocked) {
        badge.className = 'status-pill unlocked';
        badge.innerText = 'Gate Unlocked';
        gateBox.innerText = 'OPEN (ACTIVE)';
        leasesBox.innerText = (state.active_leases_count || 1) + ' ACTIVE';
      } else {
        badge.className = 'status-pill locked';
        badge.innerText = 'Physically Locked';
        gateBox.innerText = 'LOCKED';
        leasesBox.innerText = '0 ACTIVE';
      }
    }

    function renderAudits(audits) {
      const tbody = document.getElementById('auditRows');
      if (!audits || audits.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--text-muted);">No executions recorded yet.</td></tr>';
        return;
      }
      tbody.innerHTML = audits.map(a => {
        const time = a.timestamp.replace('T', ' ').substring(11, 19);
        let badgeClass = 'badge-success';
        if (a.status === 'ERROR') badgeClass = 'badge-error';
        if (a.status === 'LOCKED') badgeClass = 'badge-locked';

        return '<tr>' +
          '<td>' + escapeHTML(time) + '</td>' +
          '<td><code>' + escapeHTML(a.tool_name) + '</code></td>' +
          '<td>' + escapeHTML(a.client_ip) + '<span class="country-tag">' + escapeHTML(a.country) + '</span></td>' +
          '<td>' + escapeHTML(a.duration_ms) + ' ms</td>' +
          '<td><span class="badge ' + badgeClass + '">' + escapeHTML(a.status) + '</span></td>' +
          '<td style="color:var(--text-muted);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">' + escapeHTML(a.message || '-') + '</td>' +
          '</tr>';
      }).join('');
    }

    function showAlert(msg, isError) {
      const alert = document.getElementById('msgAlert');
      alert.style.display = 'block';
      alert.style.background = isError ? 'rgba(218,54,51,0.2)' : 'rgba(35,134,54,0.2)';
      alert.style.color = isError ? '#f85149' : '#3fb950';
      alert.style.border = '1px solid ' + (isError ? '#da3633' : '#238636');
      alert.innerText = msg;
      setTimeout(() => { alert.style.display = 'none'; }, 4000);
    }

    async function lockGate() {
      try {
        const res = await fetch('/gate/api/lock?token=' + encodeURIComponent(token), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' }
        });
        const data = await res.json();
        showAlert(data.message || "Gate locked", false);
        fetchStatus();
      } catch (e) {
        showAlert("Network error: " + e.message, true);
      }
    }

    fetchStatus();
    setInterval(fetchStatus, 3000);
  </script>
</body>
</html>
`
