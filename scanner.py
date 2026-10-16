<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>IP 段扫描时间估算器</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, 'Segoe UI', 'Microsoft YaHei', sans-serif;
    background: #f5f7fa;
    color: #1e293b;
    padding: 30px 20px;
    min-height: 100vh;
    display: flex;
    justify-content: center;
  }
  .container {
    max-width: 960px;
    width: 100%;
    background: #fff;
    border-radius: 16px;
    box-shadow: 0 4px 24px rgba(0,0,0,0.08);
    padding: 30px 36px;
  }
  h1 {
    font-size: 22px;
    font-weight: 700;
    margin-bottom: 6px;
    color: #1e40af;
  }
  .subtitle {
    color: #64748b;
    font-size: 13px;
    margin-bottom: 24px;
    padding-left: 12px;
    border-left: 3px solid #3b82f6;
    line-height: 1.7;
  }
  label {
    display: block;
    font-weight: 600;
    font-size: 13px;
    margin-bottom: 6px;
    color: #334155;
  }
  textarea {
    width: 100%;
    min-height: 160px;
    padding: 14px 16px;
    border: 1.5px solid #cbd5e1;
    border-radius: 10px;
    font-family: 'Consolas', 'Monaco', monospace;
    font-size: 13px;
    line-height: 1.7;
    resize: vertical;
    background: #fafbfc;
    transition: border-color 0.2s, box-shadow 0.2s;
  }
  textarea:focus {
    outline: none;
    border-color: #3b82f6;
    box-shadow: 0 0 0 4px rgba(59,130,246,0.12);
    background: #fff;
  }

  .input-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 14px;
    margin: 16px 0;
  }
  .input-field input[type="number"] {
    width: 100%;
    padding: 11px 13px;
    border: 1.5px solid #cbd5e1;
    border-radius: 10px;
    font-family: 'Consolas', monospace;
    font-size: 15px;
    background: #fafbfc;
    transition: border-color 0.2s, box-shadow 0.2s;
  }
  .input-field input[type="number"]:focus {
    outline: none;
    border-color: #3b82f6;
    box-shadow: 0 0 0 4px rgba(59,130,246,0.12);
    background: #fff;
  }
  .input-field .hint {
    font-size: 11px;
    color: #94a3b8;
    margin-top: 4px;
    font-family: 'Consolas', monospace;
  }

  .buttons {
    display: flex;
    gap: 10px;
    margin: 16px 0;
    flex-wrap: wrap;
  }
  button {
    padding: 10px 22px;
    border: none;
    border-radius: 8px;
    font-size: 14px;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.15s;
  }
  .btn-primary { background: #3b82f6; color: #fff; }
  .btn-primary:hover { background: #2563eb; }
  .btn-secondary { background: #e2e8f0; color: #334155; }
  .btn-secondary:hover { background: #cbd5e1; }
  .btn-preset { background: #dbeafe; color: #1e40af; font-size: 13px; padding: 8px 16px; }
  .btn-preset:hover { background: #bfdbfe; }
  .btn-preset.active { background: #3b82f6; color: #fff; }

  .error {
    background: #fef2f2;
    border: 1px solid #fecaca;
    color: #b91c1c;
    padding: 12px 16px;
    border-radius: 8px;
    font-size: 13px;
    margin-top: 12px;
    display: none;
  }
  .error.show { display: block; }
  .error .title { font-weight: 700; margin-bottom: 6px; }
  .error .item {
    font-family: 'Consolas', monospace;
    font-size: 12px;
    padding: 3px 0;
    border-bottom: 1px dashed #fecaca;
  }
  .error .item:last-child { border-bottom: none; }

  .results { margin-top: 20px; display: none; }
  .results.show { display: block; }
  .summary-cards {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 12px;
    margin-bottom: 22px;
  }
  .card {
    background: linear-gradient(135deg, #f0f9ff, #e0f2fe);
    border: 1px solid #bae6fd;
    border-radius: 12px;
    padding: 16px 18px;
  }
  .card .label {
    font-size: 12px;
    color: #0369a1;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-bottom: 6px;
  }
  .card .value {
    font-size: 22px;
    font-weight: 700;
    color: #0c4a6e;
    font-family: 'Consolas', monospace;
  }
  .card.warn {
    background: linear-gradient(135deg, #fef3c7, #fde68a);
    border-color: #fcd34d;
  }
  .card.warn .label { color: #92400e; }
  .card.warn .value { color: #78350f; }

  .stages {
    border: 1px solid #e2e8f0;
    border-radius: 12px;
    overflow: hidden;
    margin-bottom: 22px;
  }
  .stages table { width: 100%; border-collapse: collapse; font-size: 14px; }
  .stages thead { background: #f1f5f9; }
  .stages th {
    padding: 10px 14px;
    text-align: left;
    font-size: 12px;
    font-weight: 700;
    color: #475569;
    text-transform: uppercase;
    letter-spacing: 0.4px;
    border-bottom: 1px solid #e2e8f0;
  }
  .stages td {
    padding: 11px 14px;
    border-bottom: 1px solid #f1f5f9;
    font-family: 'Consolas', monospace;
    font-size: 13px;
  }
  .stages tbody tr:last-child td { border-bottom: none; }
  .stages tbody tr:hover td { background: #f8fafc; }
  .stages .stage-name {
    font-weight: 600;
    color: #1e40af;
    font-family: -apple-system, sans-serif;
    font-size: 14px;
  }
  .stages .time-cell { color: #059669; font-weight: 700; }
  .stages .time-cell.long { color: #dc2626; }
  .stages .note {
    color: #94a3b8;
    font-size: 12px;
    font-family: -apple-system, sans-serif;
  }
  .total-block {
    background: #0f172a;
    color: #e2e8f0;
    border-radius: 12px;
    padding: 20px 24px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 12px;
  }
  .total-block .label { font-size: 14px; color: #94a3b8; }
  .total-block .value {
    font-size: 28px;
    font-weight: 700;
    color: #10b981;
    font-family: 'Consolas', monospace;
  }
  .total-block .hint {
    font-size: 12px;
    color: #64748b;
    margin-top: 4px;
  }
  .footer {
    margin-top: 22px;
    padding-top: 16px;
    border-top: 1px solid #e2e8f0;
    font-size: 12px;
    color: #94a3b8;
    text-align: center;
    line-height: 1.7;
  }
  .preset-row {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
    margin-bottom: 8px;
    align-items: center;
  }
  .preset-label {
    font-size: 12px;
    color: #64748b;
    font-weight: 600;
    margin-right: 4px;
  }
</style>
</head>
<body>
<div class="container">
  <h1>🎯 IP 段扫描时间估算器</h1>
  <div class="subtitle">
    输入 IP 段 + 并发参数，估算完整扫描流程耗时<br>
    默认：40 × 20 并发、TCP_TIMEOUT=1.5s、8 分片、175 探针端口、GitHub 4 核 16G
  </div>

  <label for="input">IP 段列表（每行一个，支持 CIDR / 起止范围 / 单 IP / QQWry 导出格式）</label>
  <textarea id="input" placeholder="示例：
59.71.106.0/24
183.172.0.0 - 183.172.255.255
114.214.160.0 - 114.214.255.255
[1]	202.38.64.0 - 202.38.127.255 | 中国 安徽 合肥 中国科学技术大学 教育网 CN AS
59.71.106.5"></textarea>

  <div class="preset-row" style="margin-top:14px;">
    <span class="preset-label">快速预设：</span>
    <button class="btn-preset" onclick="applyPreset(20,10,1.5)">20 × 10 / 1.5s（基线）</button>
    <button class="btn-preset" onclick="applyPreset(25,15,1.5)">25 × 15 / 1.5s（375并发）</button>
    <button class="btn-preset" onclick="applyPreset(30,20,1.5)">30 × 20 / 1.5s（600并发）</button>
    <button class="btn-preset" onclick="applyPreset(40,20,1.5)">40 × 20 / 1.5s（800并发）</button>
    <button class="btn-preset" onclick="applyPreset(40,25,1.5)">40 × 25 / 1.5s（1000并发）</button>
    <button class="btn-preset" onclick="applyPreset(40,25,1.0)">40 × 25 / 1.0s（激进）</button>
  </div>

  <div class="input-grid">
    <div class="input-field">
      <label for="tcpWorkersInput">TCP 并发数</label>
      <input type="number" id="tcpWorkersInput" min="1" max="200" value="40">
      <div class="hint">TCP_WORKERS</div>
    </div>
    <div class="input-field">
      <label for="portWorkersInput">端口并发数</label>
      <input type="number" id="portWorkersInput" min="1" max="200" value="20">
      <div class="hint">PORT_WORKERS</div>
    </div>
    <div class="input-field">
      <label for="tcpTimeoutInput">TCP 超时（秒）</label>
      <input type="number" id="tcpTimeoutInput" min="0.1" max="10" step="0.1" value="1.5">
      <div class="hint">TCP_TIMEOUT</div>
    </div>
    <div class="input-field">
      <label for="surviveInput">预估存活 IP 数</label>
      <input type="number" id="surviveInput" min="0" value="0" placeholder="例如 500">
      <div class="hint">经验：0.5% ~ 1%</div>
    </div>
  </div>

  <div class="buttons">
    <button class="btn-primary" onclick="calculate()">📊 计算</button>
    <button class="btn-secondary" onclick="loadExample()">📋 载入示例</button>
    <button class="btn-secondary" onclick="clearAll()">🗑 清空</button>
  </div>

  <div class="error" id="errorBox">
    <div class="title">❌ 无法识别的行（已忽略）：</div>
    <div id="errorItems"></div>
  </div>

  <div class="results" id="results">
    <div class="summary-cards">
      <div class="card">
        <div class="label">总 IP 数</div>
        <div class="value" id="totalIPs">—</div>
      </div>
      <div class="card">
        <div class="label">每分片 IP 数</div>
        <div class="value" id="perShard">—</div>
      </div>
      <div class="card">
        <div class="label">全局并发</div>
        <div class="value" id="concurrency">—</div>
      </div>
      <div class="card">
        <div class="label">task/s</div>
        <div class="value" id="taskRate">—</div>
      </div>
      <div class="card">
        <div class="label">common 轮数</div>
        <div class="value" id="rounds">—</div>
      </div>
    </div>

    <div class="stages">
      <table>
        <thead>
          <tr>
            <th style="width:28%">阶段</th>
            <th style="width:22%">预估耗时</th>
            <th>说明</th>
          </tr>
        </thead>
        <tbody id="stagesBody"></tbody>
      </table>
    </div>

    <div class="total-block">
      <div>
        <div class="label">总预估耗时</div>
        <div class="value" id="totalTime">—</div>
        <div class="hint" id="totalHint"></div>
      </div>
    </div>
  </div>

  <div class="footer">
    <span id="footerParams">参数：40 × 20 = 800 并发 · TCP_TIMEOUT = 1.5s</span><br>
    8 分片并行 · 175 探针端口（12 探针 + 171 代理去重）· IP 级短路 · 单轮上限 5.8 小时 · GitHub 4 核 16G
  </div>
</div>

<script>
  // ============ 常量 ============
  // AVG_PORTS: IP 级短路后平均实际扫的端口数（基于多组实测反推，~170）
  const AVG_PORTS = 170;
  const IP_COOLDOWN = 0.5;              // 每 IP 扫完的固定等待
  const SHARD_TOTAL = 8;
  const MAX_RUNTIME_SEC = 5.8 * 3600;
  const PROXY_SEC_PER_IP = 30;          // proxy 阶段每 IP 耗时（171 端口 + 读秀验证）
  const OVERHEAD_SEC = 300;             // merge + 调度开销

  // ============ IP 解析 ============
  function ipToInt(ip) {
    const parts = ip.split('.');
    if (parts.length !== 4) return null;
    let n = 0;
    for (const p of parts) {
      const v = parseInt(p, 10);
      if (isNaN(v) || v < 0 || v > 255) return null;
      n = (n << 8) | v;
    }
    return n >>> 0;
  }

  function parseRange(line) {
    line = line.trim();
    if (!line || line.startsWith('#')) return null;

    for (const tok of line.split(/\s+/)) {
      const m = tok.match(/^(\d+\.\d+\.\d+\.\d+)\/(\d+)$/);
      if (m) {
        const ip = ipToInt(m[1]);
        const prefix = parseInt(m[2], 10);
        if (ip === null || prefix < 0 || prefix > 32) continue;
        const mask = prefix === 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) >>> 0;
        const start = (ip & mask) >>> 0;
        const end = (start | (~mask >>> 0)) >>> 0;
        return { start, end };
      }
    }

    const mRange = line.match(/(\d+\.\d+\.\d+\.\d+)\s*-\s*(\d+\.\d+\.\d+\.\d+)/);
    if (mRange) {
      const a = ipToInt(mRange[1]);
      const b = ipToInt(mRange[2]);
      if (a !== null && b !== null) {
        return { start: Math.min(a, b), end: Math.max(a, b) };
      }
    }

    const mSingle = line.match(/(\d+\.\d+\.\d+\.\d+)/);
    if (mSingle) {
      const ip = ipToInt(mSingle[1]);
      if (ip !== null) return { start: ip, end: ip };
    }

    return null;
  }

  // ============ 数字格式化 ============
  function fmtNum(n) {
    return n.toLocaleString('en-US');
  }

  function fmtTime(seconds) {
    if (seconds < 60) return seconds.toFixed(0) + ' 秒';
    if (seconds < 3600) return (seconds / 60).toFixed(1) + ' 分钟';
    if (seconds < 86400) {
      const h = Math.floor(seconds / 3600);
      const m = Math.round((seconds % 3600) / 60);
      return h + ' 小时 ' + m + ' 分';
    }
    const d = Math.floor(seconds / 86400);
    const h = Math.round((seconds % 86400) / 3600);
    return d + ' 天 ' + h + ' 小时';
  }

  // ============ 核心公式 ============
  // 秒/IP = AVG_PORTS × TCP_TIMEOUT / 全局并发 + IP_COOLDOWN / TCP_WORKERS
  // 说明：cooldown 由多个 worker 并行分摊，所以除以 TCP_WORKERS
  function secPerIp(tcpTimeout, tcpWorkers, portWorkers) {
    const concurrency = tcpWorkers * portWorkers;
    return (AVG_PORTS * tcpTimeout) / concurrency + (IP_COOLDOWN / tcpWorkers);
  }

  function taskPerSec(tcpTimeout, tcpWorkers, portWorkers) {
    const concurrency = tcpWorkers * portWorkers;
    return concurrency / tcpTimeout;
  }

  // ============ 主逻辑 ============
  function calculate() {
    const text = document.getElementById('input').value;
    const tcpWorkers = Math.max(1, parseInt(document.getElementById('tcpWorkersInput').value, 10) || 40);
    const portWorkers = Math.max(1, parseInt(document.getElementById('portWorkersInput').value, 10) || 20);
    const tcpTimeout = Math.max(0.1, parseFloat(document.getElementById('tcpTimeoutInput').value) || 1.5);
    const surviveIPs = Math.max(0, parseInt(document.getElementById('surviveInput').value, 10) || 0);

    const lines = text.split(/\r?\n/);
    let totalIPs = 0;
    const errors = [];

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      const r = parseRange(trimmed);
      if (r) {
        totalIPs += (r.end - r.start + 1);
      } else {
        errors.push(trimmed);
      }
    }

    const errBox = document.getElementById('errorBox');
    const errItems = document.getElementById('errorItems');
    if (errors.length > 0) {
      errBox.classList.add('show');
      errItems.innerHTML = errors.map(e =>
        '<div class="item">' + escapeHtml(e) + '</div>'
      ).join('');
    } else {
      errBox.classList.remove('show');
      errItems.innerHTML = '';
    }

    if (totalIPs === 0) {
      document.getElementById('results').classList.remove('show');
      return;
    }

    const perShard = Math.ceil(totalIPs / SHARD_TOTAL);
    const secPerIpValue = secPerIp(tcpTimeout, tcpWorkers, portWorkers);
    const tps = taskPerSec(tcpTimeout, tcpWorkers, portWorkers);
    const concurrency = tcpWorkers * portWorkers;

    // common 阶段：每分片独立跑
    const commonSec = perShard * secPerIpValue;
    const commonRounds = Math.ceil(commonSec / MAX_RUNTIME_SEC);
    const commonRealSec = commonSec <= MAX_RUNTIME_SEC ? commonSec : (commonRounds * MAX_RUNTIME_SEC);

    // revalidate：只扫"有代理的 IP"（约存活 IP 的 5-10%），耗时很小
    // 保守用 5% 估算
    const proxyIPs = Math.max(0, Math.round(surviveIPs * 0.05));
    const revalidateSec = proxyIPs > 0 ? (proxyIPs * secPerIpValue / SHARD_TOTAL) : 0;

    // proxy：171 端口 + 读秀验证（被 VERIFY_RATE_LIMIT 限制，与并发无关）
    const proxySec = proxyIPs > 0 ? (proxyIPs * PROXY_SEC_PER_IP / SHARD_TOTAL) : 0;

    const totalSec = commonRealSec + revalidateSec + proxySec + OVERHEAD_SEC;

    // 卡片
    document.getElementById('totalIPs').textContent = fmtNum(totalIPs);
    document.getElementById('perShard').textContent = fmtNum(perShard);
    document.getElementById('concurrency').textContent = concurrency;
    document.getElementById('taskRate').textContent = tps.toFixed(0);
    document.getElementById('rounds').textContent =
      (commonRounds > 1 ? commonRounds + ' 轮' : '1 轮');

    // 阶段表
    const tbody = document.getElementById('stagesBody');
    const rows = [];

    rows.push(`
      <tr>
        <td class="stage-name">common</td>
        <td class="time-cell ${commonRealSec > 3600 ? 'long' : ''}">${fmtTime(commonRealSec)}</td>
        <td class="note">
          8 分片 × ${fmtNum(perShard)} IP × ${secPerIpValue.toFixed(2)} s
          ${commonRounds > 1 ? '（需 ' + commonRounds + ' 轮自动续跑）' : ''}
        </td>
      </tr>
    `);

    if (surviveIPs > 0) {
      rows.push(`
        <tr>
          <td class="stage-name">revalidate</td>
          <td class="time-cell">${fmtTime(revalidateSec)}</td>
          <td class="note">只扫有代理的 IP（约 ${fmtNum(proxyIPs)} 个，存活 IP 的 5%）</td>
        </tr>
      `);
      rows.push(`
        <tr>
          <td class="stage-name">proxy</td>
          <td class="time-cell ${proxySec > 3600 ? 'long' : ''}">${fmtTime(proxySec)}</td>
          <td class="note">171 端口 + 读秀单验证（约 ${fmtNum(proxyIPs)} 个 IP）</td>
        </tr>
      `);
    } else {
      rows.push(`
        <tr>
          <td class="stage-name">revalidate / proxy</td>
          <td class="time-cell">—</td>
          <td class="note">存活 IP 为 0，跳过</td>
        </tr>
      `);
    }

    rows.push(`
      <tr>
        <td class="stage-name">merge + 调度</td>
        <td class="time-cell">${fmtTime(OVERHEAD_SEC)}</td>
        <td class="note">GitHub Actions 阶段切换开销（每轮续跑都算一次）</td>
      </tr>
    `);

    tbody.innerHTML = rows.join('');

    document.getElementById('totalTime').textContent = fmtTime(totalSec);

    let hint = '';
    if (commonRounds > 1) {
      hint = '⚠️ common 阶段超过 5.8 小时，需 ' + commonRounds + ' 轮自动续跑';
    } else if (totalSec > 3600) {
      hint = '✅ 一轮内跑完，全程自动';
    } else {
      hint = '✅ 快速完成，一轮即可';
    }
    document.getElementById('totalHint').textContent = hint;

    // footer 参数
    document.getElementById('footerParams').textContent =
      '参数：' + tcpWorkers + ' × ' + portWorkers + ' = ' + concurrency +
      ' 并发 · TCP_TIMEOUT = ' + tcpTimeout + 's · 约 ' + secPerIpValue.toFixed(2) + ' 秒/IP';

    document.getElementById('results').classList.add('show');
  }

  function escapeHtml(s) {
    const d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
  }

  function applyPreset(tw, pw, timeout) {
    document.getElementById('tcpWorkersInput').value = tw;
    document.getElementById('portWorkersInput').value = pw;
    document.getElementById('tcpTimeoutInput').value = timeout;
    calculate();
  }

  function loadExample() {
    document.getElementById('input').value =
`[36]	183.172.0.0 - 183.172.255.255 | 中国 北京 北京 清华大学教育网 教育网 CN AS
[37]	183.173.0.0 - 183.173.127.255 | 中国 北京 北京 清华大学教育网 教育网 CN AS
[38]	183.173.128.0 - 183.173.159.255 | 中国 北京 北京 清华大学教育网 教育网 CN AS`;
    document.getElementById('surviveInput').value = '515';
    calculate();
  }

  function clearAll() {
    document.getElementById('input').value = '';
    document.getElementById('surviveInput').value = '0';
    document.getElementById('results').classList.remove('show');
    document.getElementById('errorBox').classList.remove('show');
  }

  // 实时计算
  const inputs = ['input', 'tcpWorkersInput', 'portWorkersInput', 'tcpTimeoutInput', 'surviveInput'];
  inputs.forEach(id => {
    const el = document.getElementById(id);
    el.addEventListener('input', () => {
      if (document.getElementById('input').value.trim()) {
        calculate();
      } else {
        document.getElementById('results').classList.remove('show');
      }
    });
  });

  window.addEventListener('DOMContentLoaded', () => {
    loadExample();
    calculate();
  });
</script>
</body>
</html>
