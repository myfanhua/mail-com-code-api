const accountsBody = document.querySelector('#accounts');
const toast = document.querySelector('#toast');
const accountsStorageKey = 'mail-code-accounts';
const routesStorageKey = 'mail-code-routes';
const adminTokenStorageKey = 'mail-code-admin-token';
const splitDomainStorageKey = 'mail-code-split-domains';
const splitExcludeDomainStorageKey = 'mail-code-split-exclude-domains';
let savedAccounts = readSavedAccounts();
let motherAccounts = [];
let addressRows = [];
let motherPage = 1;
let motherTotalPages = 1;
let motherSearch = '';
let addressPage = 1;
let addressTotalPages = 1;
const sqlPageSize = 10;
let adminToken = localStorage.getItem(adminTokenStorageKey) || sessionStorage.getItem(adminTokenStorageKey) || '';
let adminAuthenticated = false;
const proxyPoolInput = document.querySelector('#proxy-pool-input');
const proxyPoolStatus = document.querySelector('#proxy-pool-status');
const splitProgress = document.querySelector('#split-progress');
const splitDomainInput = document.querySelector('#import-split-domain');
const splitExcludeDomainInput = document.querySelector('#import-exclude-domains');
let healthPollingTimer = null;
let healthPollingInFlight = false;

function notify(message, error = false) {
  toast.textContent = message;
  toast.style.background = error ? '#a9433d' : '#10212b';
  toast.classList.add('show');
  setTimeout(() => toast.classList.remove('show'), 2800);
}

async function copyText(text) {
  if (navigator.clipboard?.writeText && window.isSecureContext) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {}
  }

  const textarea = document.createElement('textarea');
  textarea.value = text;
  textarea.setAttribute('readonly', '');
  textarea.style.position = 'fixed';
  textarea.style.left = '-9999px';
  textarea.style.top = '0';
  document.body.appendChild(textarea);
  textarea.focus();
  textarea.select();
  textarea.setSelectionRange(0, textarea.value.length);
  let copied = false;
  try {
    copied = document.execCommand('copy');
  } catch {}
  textarea.remove();
  if (!copied) {
    window.prompt('浏览器无法自动复制，请手动复制以下内容：', text);
  }
  return copied;
}

async function request(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (adminToken) headers.set('Authorization', `Bearer ${adminToken}`);
  const response = await fetch(path, {...options, headers});
  const type = response.headers.get('content-type') || '';
  const body = type.includes('json') ? await response.json() : await response.text();
  if (!response.ok) throw new Error(body?.detail || body?.error || `HTTP ${response.status}`);
  return body;
}

function setAdminAuthenticated(authenticated) {
  adminAuthenticated = authenticated;
  const status = document.querySelector('#admin-auth-status');
  const button = document.querySelector('#admin-login');
  document.querySelector('#admin-access').hidden = authenticated;
  document.querySelector('#admin-content').hidden = !authenticated;
  status.textContent = authenticated ? '验证成功，已在当前浏览器记住' : '请输入 data/admin.token';
  button.textContent = authenticated ? '重新验证' : '验证';
  document.querySelectorAll('#import, #export, #refresh, #refresh-mothers, #copy-mother-routes, #query, #save-proxy-pool, #copy-routes, #copy-result')
    .forEach(control => { control.disabled = !authenticated; });
  if (!authenticated) {
    renderMotherAccounts([]);
    renderAddressRows([]);
  }
}

async function authenticateAdmin() {
  const input = document.querySelector('#admin-token');
  const candidate = input.value.trim();
  if (!candidate) return notify('请输入 admin.token', true);
  adminToken = candidate;
  try {
    await request('/admin/accounts?page=1&page_size=1');
    localStorage.setItem(adminTokenStorageKey, adminToken);
    sessionStorage.removeItem(adminTokenStorageKey);
    input.value = '';
    setAdminAuthenticated(true);
    await Promise.all([refreshMotherAccounts(false), refreshAddressRows(false)]);
    notify('管理员验证成功');
  } catch (error) {
    adminToken = '';
    localStorage.removeItem(adminTokenStorageKey);
    sessionStorage.removeItem(adminTokenStorageKey);
    setAdminAuthenticated(false);
    notify(`管理员验证失败：${error.message}`, true);
  }
}

function renderMotherAccounts(accounts) {
  const container = document.querySelector('#mother-accounts');
  const status = document.querySelector('#mother-list-status');
  if (!accounts.length) {
    container.innerHTML = '<div class="empty">暂无母号</div>';
    status.textContent = '共 0 个母号';
    return;
  }
  container.innerHTML = accounts.map(account => {
    const addresses = Array.isArray(account.addresses) ? account.addresses : [];
    const children = addresses.filter(route => !route.is_primary);
    return `
      <details class="mother-account">
        <summary>
          <span class="mother-email">${escapeHtml(account.email)}</span>
          <button class="copy copy-mother-group" data-account-id="${escapeHtml(account.id)}">复制母号和子号</button>
          <button class="copy split-mother" data-account-id="${escapeHtml(account.id)}">分裂</button>
          <button class="copy danger delete-mother" data-account-id="${escapeHtml(account.id)}">删除母号</button>
          <span class="mother-password">密码：${escapeHtml(account.password || '—')}</span>
          <span class="status ${statusClass(account.status)}">${escapeHtml(account.status || '未知')}</span>
          <span class="mother-meta">子号 ${children.length} 个 · ${account.proxy_bound ? '已绑定代理' : '未绑定代理'}</span>
        </summary>
        <div class="mother-children">
          ${children.length ? children.map(route => `
            <div class="mother-child-row">
              <span>${escapeHtml(route.address)}</span>
              <span class="route" title="${escapeHtml(route.url)}">${escapeHtml(route.url)}</span>
              <span class="mother-child-actions">
                <button class="copy copy-child" data-address="${escapeHtml(route.address)}" data-url="${escapeHtml(route.url)}">复制</button>
                <button class="copy danger delete-child" data-account-id="${escapeHtml(account.id)}" data-address="${escapeHtml(route.address)}">删除</button>
              </span>
            </div>
          `).join('') : '<div class="empty mother-empty">该母号暂无子号</div>'}
        </div>
      </details>`;
  }).join('');
  container.querySelectorAll('.copy-child').forEach(button => button.addEventListener('click', async () => {
    if (!await copyText(`${button.dataset.address}----${button.dataset.url}`)) return;
    notify('子号和取码地址已复制');
  }));
  container.querySelectorAll('.copy-mother-group').forEach(button => button.addEventListener('click', async event => {
    event.preventDefault();
    event.stopPropagation();
    const account = motherAccounts.find(item => String(item.id) === button.dataset.accountId);
    const lines = (account?.addresses || []).map(route => `${route.address}----${route.url}`);
    if (!lines.length) return notify('该母号没有可复制的取码地址', true);
    if (!await copyText(lines.join('\n'))) return;
    notify(`已复制该母号及其 ${Math.max(0, lines.length - 1)} 个子号`);
  }));
  container.querySelectorAll('.split-mother').forEach(button => button.addEventListener('click', async event => {
    event.preventDefault();
    event.stopPropagation();
    const account = motherAccounts.find(item => String(item.id) === button.dataset.accountId);
    if (!account) return;
    const rawCount = window.prompt(`为 ${account.email} 创建几个子号？请输入 1-9：`, '1');
    if (rawCount === null) return;
    const count = Number(rawCount);
    if (!Number.isInteger(count) || count < 1 || count > 9) return notify('分裂数量必须是 1-9', true);
    const cachedDomains = localStorage.getItem(splitDomainStorageKey) || '';
    const domain = window.prompt('指定域名（多个域名会随机选择；留空则下一步选择随机 .com/.net）：', cachedDomains);
    if (domain === null) return;
    let randomDomainTlds = [];
    if (!domain.trim()) {
      const rawTlds = window.prompt('随机域名后缀：输入 com、net 或 com,net：', 'com,net');
      if (rawTlds === null) return;
      randomDomainTlds = [...new Set(rawTlds.toLowerCase().split(/[\s,，]+/).map(value => value.replace(/^\./, '')).filter(Boolean))];
      if (!randomDomainTlds.length || randomDomainTlds.some(value => !['com', 'net'].includes(value))) {
        return notify('随机域名后缀只能填写 com、net 或 com,net', true);
      }
    }
    const cachedExcludes = localStorage.getItem(splitExcludeDomainStorageKey) || '';
    const excludeDomains = window.prompt('排除域名（可留空，多个用逗号分隔）：', cachedExcludes);
    if (excludeDomains === null) return;
    if (domain.trim()) {
      splitDomainInput.value = domain.trim();
      saveSplitDomains();
    } else {
      splitDomainInput.value = '';
      saveSplitDomains();
    }
    splitExcludeDomainInput.value = excludeDomains.trim();
    saveSplitExcludeDomains();
    button.disabled = true;
    try {
      const result = await request('/admin/aliases/split', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
          email: account.email,
          password: account.password,
          count,
          ...(domain.trim() ? {domain: domain.trim()} : {}),
          ...(randomDomainTlds.length ? {random_domain_tlds: randomDomainTlds} : {}),
          ...(excludeDomains.trim() ? {exclude_domains: excludeDomains.trim()} : {}),
        }),
      });
      motherPage = 1;
      addressPage = 1;
      await Promise.all([refreshMotherAccounts(false), refreshAddressRows(false)]);
      notify(`已为 ${account.email} 创建 ${result.created || 0} 个子号`);
    } catch (error) {
      notify(error.message, true);
    } finally {
      button.disabled = false;
    }
  }));
  container.querySelectorAll('.delete-child').forEach(button => button.addEventListener('click', async event => {
    event.preventDefault();
    event.stopPropagation();
    const account = motherAccounts.find(item => String(item.id) === button.dataset.accountId);
    if (!account || !confirm(`确定删除子号 ${button.dataset.address} 吗？`)) return;
    button.disabled = true;
    try {
      await request('/admin/aliases/delete', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({account: account.id, address: button.dataset.address}),
      });
      savedAccounts.forEach(item => {
        if (item.email === account.email) {
          item.addresses = item.addresses.filter(route => route.address !== button.dataset.address);
        }
      });
      saveAccounts(savedAccounts);
      await Promise.all([refreshMotherAccounts(false), refreshAddressRows(false)]);
      notify('子号已删除');
    } catch (error) {
      notify(error.message, true);
      button.disabled = false;
    }
  }));
  container.querySelectorAll('.delete-mother').forEach(button => button.addEventListener('click', async event => {
    event.preventDefault();
    event.stopPropagation();
    const account = motherAccounts.find(item => String(item.id) === button.dataset.accountId);
    if (!account || !confirm(`确定从系统中删除母号 ${account.email} 及其所有本地子号和取码地址吗？`)) return;
    button.disabled = true;
    try {
      await request('/admin/accounts/delete', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({account: account.id}),
      });
      savedAccounts = savedAccounts.filter(item => item.email !== account.email);
      saveAccounts(savedAccounts);
      motherPage = 1;
      addressPage = 1;
      await Promise.all([refreshMotherAccounts(false), refreshAddressRows(false)]);
      notify('母号及其本地数据已删除');
    } catch (error) {
      notify(error.message, true);
      button.disabled = false;
    }
  }));
  const childCount = accounts.reduce(
    (sum, account) => sum + (account.addresses || []).filter(route => !route.is_primary).length,
    0,
  );
  status.textContent = `共 ${accounts.length} 个母号，${childCount} 个子号`;
}

async function refreshMotherAccounts(showNotice = true) {
  try {
    const query = new URLSearchParams({
      page: String(motherPage),
      page_size: String(sqlPageSize),
      ...(motherSearch ? {q: motherSearch} : {}),
    });
    const result = await request(`/admin/accounts?${query}`);
    motherAccounts = Array.isArray(result.accounts) ? result.accounts : [];
    const pagination = result.pagination || {};
    motherPage = Number(pagination.page || 1);
    motherTotalPages = Number(pagination.total_pages || 1);
    renderMotherAccounts(motherAccounts);
    document.querySelector('#mother-page-status').textContent = `第 ${motherPage}/${motherTotalPages} 页，共 ${pagination.total || 0} 个母号`;
    document.querySelector('#mother-prev').disabled = motherPage <= 1;
    document.querySelector('#mother-next').disabled = motherPage >= motherTotalPages;
    document.querySelector('#account-count').textContent = pagination.total || 0;
    if (showNotice) notify('母号列表已刷新');
  } catch (error) {
    document.querySelector('#mother-list-status').textContent = error.message;
    if (showNotice) notify(error.message, true);
  }
}

function readSavedAccounts() {
  try {
    const value = JSON.parse(localStorage.getItem(accountsStorageKey) || '[]');
    if (Array.isArray(value)) return value.map(normalizeAccount).filter(account => account.email);
  } catch {}
  return [];
}

function normalizeAccount(account) {
  return {
    email: String(account?.email || '').toLowerCase(),
    password: String(account?.password || ''),
    status: String(account?.status || '已保存'),
    addresses: Array.isArray(account?.addresses) ? account.addresses.map(route => ({
      address: String(route?.address || ''),
      url: String(route?.url || ''),
    })).filter(route => route.address && route.url) : [],
  };
}

function flattenLines(accounts) {
  return accounts.flatMap(account => account.addresses.map(route => `${route.address}----${route.url}`));
}

function saveAccounts(accounts) {
  savedAccounts = accounts.map(normalizeAccount);
  localStorage.setItem(accountsStorageKey, JSON.stringify(savedAccounts));
  localStorage.setItem(routesStorageKey, JSON.stringify(flattenLines(savedAccounts)));
}

function saveSplitDomains() {
  const value = splitDomainInput.value.trim();
  if (value) localStorage.setItem(splitDomainStorageKey, value);
  else localStorage.removeItem(splitDomainStorageKey);
}

function saveSplitExcludeDomains() {
  const value = splitExcludeDomainInput.value.trim();
  if (value) localStorage.setItem(splitExcludeDomainStorageKey, value);
  else localStorage.removeItem(splitExcludeDomainStorageKey);
}

function parseCredentialLines(text) {
  return text.split(/\r?\n/).map(line => line.trim()).filter(line => line && !line.startsWith('#')).map(line => {
    const delimiter = ['----', '---', '\t', ','].find(value => line.includes(value));
    if (!delimiter) return null;
    const index = line.indexOf(delimiter);
    return {email: line.slice(0, index).trim().toLowerCase(), password: line.slice(index + delimiter.length).trim()};
  }).filter(row => row && row.email && row.password);
}

function lineToRoute(line) {
  const index = line.indexOf('----');
  if (index < 1) return null;
  return {address: line.slice(0, index), url: line.slice(index + 4)};
}

function mergeAccounts(existing, fresh) {
  const map = new Map(existing.map(normalizeAccount).map(account => [account.email, account]));
  fresh.map(normalizeAccount).forEach(account => {
    const current = map.get(account.email) || {email: account.email, password: '', status: '已保存', addresses: []};
    current.password = account.password || current.password;
    current.status = account.status || current.status;
    const routeMap = new Map(current.addresses.map(route => [route.address.toLowerCase(), route]));
    account.addresses.forEach(route => routeMap.set(route.address.toLowerCase(), route));
    current.addresses = [...routeMap.values()];
    map.set(account.email, current);
  });
  return [...map.values()];
}

function statusClass(value) {
  return value === '已验证' || value.startsWith('分裂成功') ? 'ready' : value.startsWith('分裂失败') ? 'bad' : '';
}

function splitProgressClass(job) {
  if (job.status === '成功') return 'ready';
  if (job.status === '失败') return 'bad';
  if (job.status === '运行中') return 'pending';
  return '';
}

function renderSplitProgress(jobs = []) {
  if (!splitProgress) return;
  if (!jobs.length) {
    splitProgress.hidden = true;
    splitProgress.innerHTML = '';
    return;
  }
  const done = jobs.filter(job => job.status === '成功' || job.status === '失败').length;
  const success = jobs.filter(job => job.status === '成功').length;
  const failed = jobs.filter(job => job.status === '失败').length;
  const created = jobs.reduce((sum, job) => sum + (job.created || 0), 0);
  splitProgress.hidden = false;
  splitProgress.innerHTML = `
    <div class="split-progress-head">
      <strong>分裂进度 ${done}/${jobs.length}</strong>
      <span class="muted">成功账号 ${success} 个，失败账号 ${failed} 个，已生成 ${created} 个地址</span>
    </div>
    <div class="split-progress-list">
      ${jobs.map((job, index) => `
        <div class="split-progress-row">
          <span class="split-progress-index">${index + 1}</span>
          <span class="split-progress-email">${escapeHtml(job.email)}</span>
          <span class="status ${splitProgressClass(job)}">${escapeHtml(job.status)}</span>
          <span class="split-progress-detail">${
            job.status === '成功'
              ? `生成 ${job.created || 0} 个`
              : job.error
                ? escapeHtml(job.error)
                : ''
          }</span>
        </div>
      `).join('')}
    </div>`;
}

function renderAccounts(accounts) {
  const rows = accounts.flatMap(account => account.addresses.length ? account.addresses.map(route => ({account, route})) : [{account, route: null}]);
  if (!rows.length) {
    accountsBody.innerHTML = '<tr><td colspan="6" class="empty">导入账号后显示地址</td></tr>';
    document.querySelector('#table-status').textContent = '暂无已保存账号';
    return;
  }
  accountsBody.innerHTML = rows.map(({account, route}) => `
    <tr>
      <td>${route ? `<input class="address-select" type="checkbox" data-address="${escapeHtml(route.address)}" data-url="${escapeHtml(route.url)}" aria-label="选择 ${escapeHtml(route.address)}">` : ''}</td>
      <td>${escapeHtml(route?.address || account.email)}</td>
      <td>${escapeHtml(account.email)}</td>
      <td><span class="status">${route?.address === account.email ? '母号' : '子号'}</span></td>
      <td>${route ? `<span class="route" title="${escapeHtml(route.url)}">${escapeHtml(route.url)}</span>` : '—'}</td>
      <td>${route ? `<button class="copy" data-address="${escapeHtml(route.address)}" data-url="${escapeHtml(route.url)}">复制</button>` : '—'}</td>
    </tr>`).join('');
  accountsBody.querySelectorAll('.copy').forEach(button => button.addEventListener('click', async () => {
    if (!await copyText(`${button.dataset.address}----${button.dataset.url}`)) return;
    notify('邮箱和取码地址已复制');
  }));
  document.querySelector('#address-select-all').checked = false;
  document.querySelector('#table-status').textContent = '结果已保存在当前浏览器';
}

function renderAddressRows(rows) {
  if (!rows.length) {
    accountsBody.innerHTML = '<tr><td colspan="6" class="empty">暂无接码地址</td></tr>';
    document.querySelector('#table-status').textContent = '暂无接码地址';
    return;
  }
  accountsBody.innerHTML = rows.map(route => `
    <tr>
      <td><input class="address-select" type="checkbox" data-address="${escapeHtml(route.address)}" data-url="${escapeHtml(route.url)}" aria-label="选择 ${escapeHtml(route.address)}"></td>
      <td>${escapeHtml(route.address)}</td>
      <td>${escapeHtml(route.mother_email)}</td>
      <td><span class="status ${route.is_primary ? 'ready' : ''}">${escapeHtml(route.email_type)}</span></td>
      <td><span class="route" title="${escapeHtml(route.url)}">${escapeHtml(route.url)}</span></td>
      <td><button class="copy copy-address" data-address="${escapeHtml(route.address)}" data-url="${escapeHtml(route.url)}">复制</button></td>
    </tr>`).join('');
  accountsBody.querySelectorAll('.copy-address').forEach(button => button.addEventListener('click', async () => {
    if (!await copyText(`${button.dataset.address}----${button.dataset.url}`)) return;
    notify('邮箱和取码地址已复制');
  }));
  document.querySelector('#address-select-all').checked = false;
  document.querySelector('#table-status').textContent = `当前显示 ${rows.length} 条`;
}

async function refreshAddressRows(showNotice = true) {
  try {
    const result = await request(`/admin/addresses?page=${addressPage}&page_size=${sqlPageSize}`);
    addressRows = Array.isArray(result.addresses) ? result.addresses : [];
    const pagination = result.pagination || {};
    addressPage = Number(pagination.page || 1);
    addressTotalPages = Number(pagination.total_pages || 1);
    renderAddressRows(addressRows);
    document.querySelector('#address-page-status').textContent = `第 ${addressPage}/${addressTotalPages} 页，共 ${pagination.total || 0} 个地址`;
    document.querySelector('#address-prev').disabled = addressPage <= 1;
    document.querySelector('#address-next').disabled = addressPage >= addressTotalPages;
    document.querySelector('#route-count').textContent = pagination.total || 0;
    if (showNotice) notify('接码地址已刷新');
  } catch (error) {
    document.querySelector('#table-status').textContent = error.message;
    if (showNotice) notify(error.message, true);
  }
}

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>'"]/g, character => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[character]));
}

function routeForEmail(email) {
  for (const account of savedAccounts) {
    const route = account.addresses.find(item => item.address.toLowerCase() === email.toLowerCase());
    if (route) return route;
  }
  const serverRoute = addressRows.find(item => item.address.toLowerCase() === email.toLowerCase());
  if (serverRoute) return serverRoute;
  return null;
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function routeAddresses(lines) {
  return new Set(lines.map(lineToRoute).filter(Boolean).map(route => route.address.toLowerCase()));
}

async function fetchAccountRoutes(account) {
  const result = await request('/auth/login', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({email: account.email, password: account.password}),
  });
  return (result.routes || []).map(route => ({
    address: String(route.address || '').toLowerCase(),
    url: String(route.url || ''),
  })).filter(route => route.address && route.url);
}

async function recoverRoutesAfterUncertainSplit(account, outputLines, attempts = 6) {
  const knownAccountRoutes = new Set(account.addresses.map(route => route.address.toLowerCase()));
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    if (attempt > 1) await sleep(5000);
    const routes = await fetchAccountRoutes(account);
    const outputAddresses = routeAddresses(outputLines);
    const recoveredRoutes = [];
    for (const route of routes) {
      if (!knownAccountRoutes.has(route.address)) {
        account.addresses.push(route);
        knownAccountRoutes.add(route.address);
      }
      if (!outputAddresses.has(route.address)) {
        outputLines.push(`${route.address}----${route.url}`);
        outputAddresses.add(route.address);
        recoveredRoutes.push(route);
      }
    }
    if (recoveredRoutes.length) return recoveredRoutes;
  }
  return [];
}

async function checkHealth() {
  try {
    const result = await request('/health');
    const badge = document.querySelector('#health-badge');
    badge.textContent = result.ok ? '服务正常' : '服务异常';
    badge.className = `badge ${result.ok ? 'ok' : 'bad'}`;
    if (proxyPoolStatus) {
      const stats = result.proxy_pool || {};
      proxyPoolStatus.textContent = stats.enabled
        ? `当前 ${stats.total || 0} 条，已分配 ${stats.assigned || 0} 条，剩余 ${stats.remaining || 0} 条`
        : '未配置代理池';
    }
  } catch {
    const badge = document.querySelector('#health-badge');
    badge.textContent = '无法连接';
    badge.className = 'badge bad';
    if (proxyPoolStatus) proxyPoolStatus.textContent = '无法读取状态';
  }
}

async function pollHealthOnce() {
  if (healthPollingInFlight) return;
  healthPollingInFlight = true;
  try {
    await checkHealth();
  } finally {
    healthPollingInFlight = false;
  }
}

function startHealthPolling() {
  if (healthPollingTimer) return;
  if (proxyPoolStatus) proxyPoolStatus.classList.add('live');
  pollHealthOnce();
  healthPollingTimer = setInterval(pollHealthOnce, 2000);
}

function stopHealthPolling() {
  if (!healthPollingTimer) return;
  clearInterval(healthPollingTimer);
  healthPollingTimer = null;
  if (proxyPoolStatus) proxyPoolStatus.classList.remove('live');
}

document.querySelector('#refresh').addEventListener('click', () => {
  savedAccounts = readSavedAccounts();
  motherPage = 1;
  addressPage = 1;
  refreshMotherAccounts(false);
  refreshAddressRows(false);
  notify('账号和接码地址已刷新');
});

document.querySelector('#refresh-mothers').addEventListener('click', () => {
  refreshMotherAccounts();
});

function applyMotherFilter() {
  motherSearch = document.querySelector('#mother-filter').value.trim().toLowerCase();
  motherPage = 1;
  refreshMotherAccounts(false);
}

document.querySelector('#mother-filter-submit').addEventListener('click', applyMotherFilter);
document.querySelector('#mother-filter').addEventListener('keydown', event => {
  if (event.key === 'Enter') applyMotherFilter();
});
document.querySelector('#mother-filter-clear').addEventListener('click', () => {
  document.querySelector('#mother-filter').value = '';
  motherSearch = '';
  motherPage = 1;
  refreshMotherAccounts(false);
});

document.querySelector('#mother-prev').addEventListener('click', () => {
  if (motherPage > 1) {
    motherPage -= 1;
    refreshMotherAccounts(false);
  }
});

document.querySelector('#mother-next').addEventListener('click', () => {
  if (motherPage < motherTotalPages) {
    motherPage += 1;
    refreshMotherAccounts(false);
  }
});

document.querySelector('#address-prev').addEventListener('click', () => {
  if (addressPage > 1) {
    addressPage -= 1;
    refreshAddressRows(false);
  }
});

document.querySelector('#address-next').addEventListener('click', () => {
  if (addressPage < addressTotalPages) {
    addressPage += 1;
    refreshAddressRows(false);
  }
});

document.querySelector('#import').addEventListener('click', async () => {
  const credentials = document.querySelector('#credentials').value.trim();
  if (!credentials) return notify('请先输入邮箱账号', true);
  const credentialRows = parseCredentialLines(credentials);
  const verify = document.querySelector('#verify').checked;
  const useProxy = document.querySelector('#use-proxy').checked;
  const splitCount = Number(document.querySelector('#import-split-count').value || 0);
  const splitDomain = splitDomainInput.value.trim();
  const excludeDomains = splitExcludeDomainInput.value.trim();
  saveSplitDomains();
  saveSplitExcludeDomains();
  const randomDomainTlds = [
    document.querySelector('#random-com-domain').checked ? 'com' : '',
    document.querySelector('#random-net-domain').checked ? 'net' : '',
  ].filter(Boolean);
  const status = document.querySelector('#import-status');
  status.textContent = '保存并验证中...';
  renderSplitProgress([]);
  startHealthPolling();
  try {
    const result = await request(`/admin/import?verify=${verify}&use_proxy=${useProxy}`, {method:'POST', headers:{'Content-Type':'text/plain; charset=utf-8'}, body:credentials});
    const resultByEmail = new Map((result.results || []).map(item => [item.email, item]));
    const freshAccounts = credentialRows.map(row => ({
      email: row.email,
      password: row.password,
      status: resultByEmail.get(row.email)?.verification?.ok ? '已验证' : '已保存',
      addresses: [],
    }));
    (result.lines || []).map(lineToRoute).filter(Boolean).forEach(route => {
      const account = freshAccounts.find(item => item.email === route.address.toLowerCase());
      if (account) account.addresses.push(route);
    });
    let outputLines = result.lines || [];
    const splitErrors = [];
    if (splitCount > 0) {
      status.textContent = `已导入，正在批量分裂 ${freshAccounts.length} 个账号...`;
      const splitJobs = freshAccounts.map(account => ({
        email: account.email,
        status: '等待中',
        created: 0,
        error: '',
      }));
      renderSplitProgress(splitJobs);
      for (const [index, account] of freshAccounts.entries()) {
        const job = splitJobs[index];
        const splitCreatedSoFar = outputLines.length - (result.lines || []).length;
        job.status = '运行中';
        account.status = `正在分裂 ${index + 1}/${freshAccounts.length}`;
        status.textContent = `正在分裂 ${index + 1}/${freshAccounts.length}：${account.email}，已生成 ${splitCreatedSoFar} 个，失败 ${splitErrors.length} 个`;
        renderSplitProgress(splitJobs);
        renderAccounts(mergeAccounts(savedAccounts, freshAccounts));
        try {
          const split = await request('/admin/aliases/split', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
              email: account.email,
              password: account.password,
              count: splitCount,
              ...(splitDomain ? {domain: splitDomain} : {}),
              ...(randomDomainTlds.length ? {random_domain_tlds: randomDomainTlds} : {}),
              ...(excludeDomains ? {exclude_domains: excludeDomains} : {}),
            }),
          });
          const splitRoutes = (split.routes || []).map(route => ({address: route.address, url: route.url}));
          account.addresses.push(...splitRoutes);
          account.status = `分裂成功 ${splitRoutes.length} 个`;
          job.status = '成功';
          job.created = splitRoutes.length;
          outputLines = outputLines.concat(splitRoutes.map(route => `${route.address}----${route.url}`));
        } catch (error) {
          const uncertain = /HTTP 504|上限|alias_limit|timeout|timed out/i.test(error.message);
          if (uncertain) {
            job.status = '运行中';
            job.error = '请求超时，正在回捞已生成地址...';
            account.status = '请求超时，正在回捞';
            status.textContent = `${account.email} 请求超时，正在回捞已生成地址...`;
            renderSplitProgress(splitJobs);
            try {
              const recoveredRoutes = await recoverRoutesAfterUncertainSplit(account, outputLines);
              if (recoveredRoutes.length) {
                account.status = `分裂成功 ${recoveredRoutes.length} 个（超时后回捞）`;
                job.status = '成功';
                job.created = recoveredRoutes.length;
                job.error = '';
              } else {
                account.status = `分裂失败: ${error.message}`;
                job.status = '失败';
                job.error = `${error.message}；回捞未发现新地址`;
                splitErrors.push(`${account.email}: ${job.error}`);
              }
            } catch (recoverError) {
              account.status = `分裂失败: ${error.message}`;
              job.status = '失败';
              job.error = `${error.message}；回捞失败：${recoverError.message}`;
              splitErrors.push(`${account.email}: ${job.error}`);
            }
          } else {
            account.status = `分裂失败: ${error.message}`;
            job.status = '失败';
            job.error = error.message;
            splitErrors.push(`${account.email}: ${error.message}`);
          }
        }
        const processed = index + 1;
        const splitCreatedNow = outputLines.length - (result.lines || []).length;
        status.textContent = `分裂进度 ${processed}/${freshAccounts.length}，已生成 ${splitCreatedNow} 个，失败 ${splitErrors.length} 个`;
        renderSplitProgress(splitJobs);
        renderAccounts(mergeAccounts(savedAccounts, freshAccounts));
      }
    }
    saveAccounts(mergeAccounts(savedAccounts, freshAccounts));
    motherPage = 1;
    addressPage = 1;
    refreshMotherAccounts(false);
    refreshAddressRows(false);
    document.querySelector('#import-result').value = outputLines.join('\n');
    document.querySelector('#import-result-block').hidden = false;
    renderAccounts(savedAccounts);
    const splitCreated = outputLines.length - (result.lines || []).length;
    const failureSummary = splitErrors.length ? `，失败 ${splitErrors.length} 个账号：${splitErrors.join('；')}` : '';
    status.textContent = `已保存 ${result.imported} 个账号${splitCount ? `，分裂完成 ${splitCreated} 个${failureSummary}` : ''}`;
    notify(splitErrors.length ? `导入完成，有 ${splitErrors.length} 个账号分裂失败` : `导入完成：${result.imported} 个账号`);
  } catch (error) {
    status.textContent = error.message;
    notify(error.message, true);
  } finally {
    stopHealthPolling();
    await checkHealth();
  }
});

document.querySelector('#copy-result').addEventListener('click', async () => {
  if (!await copyText(document.querySelector('#import-result').value)) return;
  notify('邮箱----接码API 已复制');
});

document.querySelector('#save-proxy-pool').addEventListener('click', async () => {
  const proxyText = (proxyPoolInput?.value || '').trim();
  if (!proxyText) return notify('请先输入代理池内容', true);
  try {
    const result = await request('/admin/proxy-pool', {
      method: 'POST',
      headers: {'Content-Type': 'text/plain; charset=utf-8'},
      body: proxyText,
    });
    if (proxyPoolStatus) {
      const stats = result.proxy_pool || {};
      proxyPoolStatus.textContent = `已保存 ${result.added || 0} 条，当前 ${stats.total || 0} 条`;
    }
    proxyPoolInput.value = '';
    notify(`代理池已保存 ${result.added || 0} 条`);
    checkHealth();
  } catch (error) {
    notify(error.message, true);
  }
});

document.querySelector('#query').addEventListener('click', async () => {
  const input = document.querySelector('#query-emails').value.trim();
  const status = document.querySelector('#query-status');
  if (!input) return notify('请先输入邮箱', true);
  const emails = input.split(/[\n,]+/).map(value => value.trim().toLowerCase()).filter(Boolean);
  const maxAge = Number(document.querySelector('#max-age').value || 600);
  status.textContent = '查询中...';
  try {
    const results = await Promise.all(emails.map(async email => {
      const route = routeForEmail(email);
      if (!route) return {email, code: null, error: 'unknown_mailbox'};
      try {
        const response = await fetch(`${route.url}?max_age=${encodeURIComponent(maxAge)}&wait=15`);
        const body = await response.json();
        return response.ok ? body : {...body, email};
      } catch {
        return {email, code: null, error: 'network_error'};
      }
    }));
    document.querySelector('#query-results').innerHTML = results.map(item => `
      <tr><td>${escapeHtml(item.email)}</td><td class="code-value">${escapeHtml(item.code || '—')}</td>
      <td>${escapeHtml(item.mail?.subject || '')}</td><td class="${item.error ? 'query-error' : 'query-ok'}">${escapeHtml(item.error || (item.code ? '已识别' : '暂无新码'))}</td></tr>`).join('');
    status.textContent = `完成 ${results.length} 个邮箱`;
  } catch (error) { status.textContent = error.message; notify(error.message, true); }
});

document.querySelector('#export').addEventListener('click', async () => {
  try {
    const lines = flattenLines(savedAccounts);
    if (!lines.length) throw new Error('当前没有已保存地址');
    const blob = new Blob([lines.join('\n') + '\n'], {type: 'text/plain;charset=utf-8'});
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = '邮箱----接码API.txt';
    link.click();
    URL.revokeObjectURL(link.href);
    notify('地址文件已下载');
  } catch (error) { notify(error.message, true); }
});

document.querySelector('#copy-routes').addEventListener('click', async () => {
  const lines = [...accountsBody.querySelectorAll('.address-select:checked')]
    .map(checkbox => `${checkbox.dataset.address}----${checkbox.dataset.url}`);
  if (!lines.length) return notify('请先勾选需要复制的接码地址', true);
  if (!await copyText(lines.join('\n'))) return;
  notify(`已复制 ${lines.length} 条勾选地址`);
});

document.querySelector('#address-select-all').addEventListener('change', event => {
  accountsBody.querySelectorAll('.address-select').forEach(checkbox => {
    checkbox.checked = event.target.checked;
  });
});

document.querySelector('#copy-mother-routes').addEventListener('click', async () => {
  const lines = motherAccounts.flatMap(account => (account.addresses || [])
    .map(route => `${route.address}----${route.url}`));
  if (!lines.length) return notify('当前页没有可复制的母号或子号', true);
  if (!await copyText(lines.join('\n'))) return;
  notify(`已复制当前页 ${lines.length} 条母号和子号地址`);
});

document.querySelector('#admin-login').addEventListener('click', authenticateAdmin);
document.querySelector('#admin-token').addEventListener('keydown', event => {
  if (event.key === 'Enter') authenticateAdmin();
});

splitDomainInput.value = localStorage.getItem(splitDomainStorageKey) || '';
splitDomainInput.addEventListener('change', saveSplitDomains);
splitDomainInput.addEventListener('blur', saveSplitDomains);
splitExcludeDomainInput.value = localStorage.getItem(splitExcludeDomainStorageKey) || '';
splitExcludeDomainInput.addEventListener('change', saveSplitExcludeDomains);
splitExcludeDomainInput.addEventListener('blur', saveSplitExcludeDomains);

setAdminAuthenticated(false);
if (adminToken) {
  document.querySelector('#admin-token').value = adminToken;
  authenticateAdmin();
}
checkHealth();
