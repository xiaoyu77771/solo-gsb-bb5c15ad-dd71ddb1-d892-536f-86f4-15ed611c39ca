/* 冷链告警抑制策略沙盒 —— 原生前端逻辑 */
"use strict";

const $ = (sel) => document.querySelector(sel);
const api = async (path, opts = {}) => {
  const res = await fetch(path, {
    headers: opts.body ? { "Content-Type": "application/json" } : {},
    ...opts,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `请求失败 HTTP ${res.status}`);
  return data;
};

let state = {
  staged: [],
  alerts: [],
  rules: [],
  runs: [],
  settings: {},
  compare: { a: null, b: null, result: null },
  events: { events: [], devices: [], gap_seconds: 900 },
  snapshots: [],
  snapCompare: { from: null, to: null, result: null },
};

function eventFilters() {
  return {
    device: $("#ev-filter-device")?.value || "",
    level: $("#ev-filter-level")?.value || "",
    status: $("#ev-filter-status")?.value || "",
    start: $("#ev-filter-start")?.value || "",
    end: $("#ev-filter-end")?.value || "",
  };
}

// ---------------------------------------------------------------------------
// 通用 UI
// ---------------------------------------------------------------------------

let toastTimer = null;
function toast(msg, isError = false) {
  const el = $("#toast");
  el.textContent = msg;
  el.className = "toast show" + (isError ? " error" : "");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (el.className = "toast"), 3200);
}
const fail = (e) => toast(e.message || String(e), true);

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function levelBadge(level) {
  const l = (level || "info").toLowerCase();
  return `<span class="level level-${l}">${esc(l)}</span>`;
}

function levelCell(level) {
  return level ? levelBadge(level) : '<span class="badge">全部 *</span>';
}

// ---------------------------------------------------------------------------
// 数据加载
// ---------------------------------------------------------------------------

async function refreshAll() {
  await Promise.all([loadStaged(), loadAlerts(), loadRules(), loadRuns(), loadSettings()]);
  renderStaged();
  renderAlerts();
  renderRules();
  renderRunSelects();
  renderSettings();
  if (state.compare.a && state.compare.b) await loadCompare();
  await loadEvents();
  await loadSnapshots();
}

async function loadStaged() {
  state.staged = await api("/api/staged");
}
async function loadAlerts() {
  state.alerts = await api("/api/alerts");
}
async function loadRules() {
  state.rules = await api("/api/rules");
}
async function loadRuns() {
  state.runs = await api("/api/runs");
}
async function loadSettings() {
  state.settings = await api("/api/settings");
}

// ---------------------------------------------------------------------------
// Tab 1: 告警注入
// ---------------------------------------------------------------------------

function renderStaged() {
  $("#staged-count").textContent = state.staged.length;
  const box = $("#staged-list");
  if (!state.staged.length) {
    box.innerHTML = '<p class="empty">队列为空，可在右侧导入 JSON 或填充内置示例</p>';
    return;
  }
  box.innerHTML = state.staged.map((item, i) => {
    const p = item.payload;
    return `<div class="staged-item">
      <span class="seq">${i + 1}</span>
      <div class="body">
        <div class="meta">${esc(p.ts || "(无 ts，用注入时刻)")} · ${esc(p.device_id || "-")} ·
          ${esc(p.batch_id || "-")} · ${levelBadge(p.level)} · ${esc(p.alert_type || "-")}</div>
        <div class="msg">${esc(p.message || "")}</div>
      </div>
      <button class="btn ghost small" data-del-staged="${item.id}">移除</button>
    </div>`;
  }).join("");
}

function renderCandidates(cands) {
  if (!cands || !cands.length) return "";
  const items = cands.map((c) => {
    const checks = (c.checks || []).map((t) => {
      const miss = t.includes("不匹配") || t.includes("不命中") || t.includes("早于") || t.includes("晚于");
      return `<li class="${miss ? "check-miss" : "check-hit"}">${esc(t)}</li>`;
    }).join("");
    return `<div class="candidate ${c.matched ? "winner" : ""}">
      <div class="cand-head">#${c.rule_id} ${esc(c.name)} · 优先级 ${c.priority} ·
        动作 ${c.action === "pass" ? "放行" : "抑制"} ${c.matched ? "— <b>匹配</b>" : "— 未匹配"}</div>
      <ul class="checks">${checks}</ul>
    </div>`;
  }).join("");
  return `<div class="candidates"><div style="color:var(--accent)">规则评估过程（按优先级）：</div>${items}</div>`;
}

function renderAlerts() {
  const rows = state.alerts;
  const tbody = $("#alerts-body");
  let passN = 0, suppressN = 0;
  if (!rows.length) {
    tbody.innerHTML = '<tr><td colspan="9" class="empty">尚未注入告警</td></tr>';
  } else {
    tbody.innerHTML = rows.map(({ alert, decision }) => {
      if (decision) {
        if (decision.decision === "pass") passN++; else suppressN++;
      }
      const d = decision
        ? `<span class="decision ${decision.decision}">${decision.decision === "pass" ? "放行 PASS" : "抑制 SUPPRESS"}</span>`
        : '<span class="badge">未评估</span>';
      const rule = decision
        ? `<div class="reason-cell">
             <div class="reason-text">${decision.rule_id ? `命中规则 #${decision.rule_id}「${esc(decision.rule_name)}」` : "无命中规则（默认策略）"}</div>
             <div style="color:var(--muted);margin-top:2px">${esc(decision.reason)}</div>
             <div style="color:var(--muted);margin-top:2px;font-size:11.5px">冷却指纹: <code>${esc(decision.fingerprint)}</code></div>
             ${renderCandidates(decision.candidates)}
           </div>`
        : '<span class="empty">-</span>';
      return `<tr>
        <td>${alert.seq}</td>
        <td>${esc(alert.ts)}</td>
        <td>${esc(alert.device_id || "-")}</td>
        <td>${esc(alert.batch_id || "-")}</td>
        <td>${levelBadge(alert.level)}</td>
        <td>${esc(alert.alert_type || "-")}</td>
        <td style="max-width:220px">${esc(alert.message || "")}</td>
        <td>${d}</td>
        <td>${rule}</td>
      </tr>`;
    }).join("");
  }
  $("#live-pass").textContent = `${passN} 放行`;
  $("#live-suppress").textContent = `${suppressN} 抑制`;
}

async function doInject(next) {
  try {
    if (next) await api("/api/alerts/inject-next", { method: "POST" });
    else await api("/api/alerts/inject-all", { method: "POST" });
    await refreshAll();
    await loadReceiverLogs();
    toast(next ? "已注入队首 1 条" : "队列已全部顺序注入");
  } catch (e) { fail(e); }
}

async function doUndo() {
  if (!state.alerts.length) return toast("没有可撤销的注入", true);
  const last = state.alerts[state.alerts.length - 1].alert;
  if (!confirm(`撤销最近注入 #${last.seq}（${last.device_id} / ${last.alert_type}）？\n该告警会退回队列头部，其在所有评估中的决定与投递日志一并删除。`)) return;
  try {
    await api("/api/alerts/undo", { method: "POST" });
    await refreshAll();
    await loadReceiverLogs();
    toast("已撤销最近注入");
  } catch (e) { fail(e); }
}

function readJsonTextarea(el) {
  const text = el.value.trim();
  if (!text) throw new Error("JSON 内容为空");
  try { return JSON.parse(text); }
  catch { throw new Error("JSON 解析失败，请检查格式"); }
}

async function doImport(append) {
  let data;
  try { data = readJsonTextarea($("#import-json")); } catch (e) { return fail(e); }
  const body = Array.isArray(data) ? { alerts: data, append } : { ...data, append: append || data.append };
  try {
    const r = await api("/api/alerts/import", { method: "POST", body: JSON.stringify(body) });
    await refreshAll();
    toast(`已${r.appended ? "追加" : "导入"} ${r.imported} 条告警到队列`);
  } catch (e) { fail(e); }
}

async function doDirectInject() {
  let data;
  try { data = readJsonTextarea($("#direct-json")); } catch (e) { return fail(e); }
  if (Array.isArray(data)) return fail("该入口仅接受单条 JSON 对象，批量导入请使用左侧");
  try {
    await api("/api/alerts/inject", { method: "POST", body: JSON.stringify(data) });
    await refreshAll();
    await loadReceiverLogs();
    toast("单条告警已注入并完成评估");
  } catch (e) { fail(e); }
}

// ---------------------------------------------------------------------------
// Tab 2: 事件关联
// ---------------------------------------------------------------------------

function fmtDuration(seconds) {
  if (seconds < 60) return `${seconds}s`;
  const m = Math.round(seconds / 60);
  if (m < 60) return `${m} 分钟`;
  const h = Math.floor(m / 60), rest = m % 60;
  return rest ? `${h} 小时 ${rest} 分` : `${h} 小时`;
}

async function loadEvents() {
  const params = new URLSearchParams();
  const f = eventFilters();
  for (const [k, v] of Object.entries(f)) {
    if (v) params.set(k, v);
  }
  const qs = params.toString();
  state.events = await api(`/api/events${qs ? `?${qs}` : ""}`);
  renderEvents();
}

function renderEventDeviceOptions() {
  const sel = $("#ev-filter-device");
  const current = sel.value;
  sel.innerHTML = '<option value="">全部设备</option>' +
    state.events.devices.map((d) =>
      `<option value="${esc(d)}">${esc(d || "(空设备)")}</option>`).join("");
  if (state.events.devices.includes(current)) sel.value = current;
}

function renderEvents() {
  const data = state.events;
  const gapInput = $("#ev-gap");
  if (!gapInput.value) gapInput.value = data.gap_seconds;
  $("#ev-gap-saved").textContent = `当前间隔 ${data.gap_seconds}s（${fmtDuration(data.gap_seconds)}）`;
  $("#ev-total").textContent = `${data.total} 事件`;
  $("#ev-acked").textContent = `${data.acknowledged_count} 已确认`;
  $("#ev-unacked").textContent = `${data.unacknowledged_count} 未确认`;
  renderEventDeviceOptions();

  const box = $("#events-list");
  if (!data.events.length) {
    box.innerHTML = '<p class="empty">没有匹配的事件。先到「告警注入」页注入告警，或调整筛选条件。</p>';
    return;
  }
  box.innerHTML = data.events.map((ev) => {
    const dur = (new Date(ev.last_ts) - new Date(ev.first_ts)) / 1000;
    const seqs = ev.member_seqs.map((s) => `<span class="seq-chip">#${s}</span>`).join(" ");
    const ack = ev.acknowledged
      ? '<span class="badge pass">✓ 已确认</span>'
      : '<span class="badge suppress">● 未确认</span>';
    const timeline = ev.members.map((m) => {
      const a = m.alert;
      const dec = m.live_decision === "pass"
        ? '<span class="decision pass small">live 放行</span>'
        : m.live_decision === "suppress"
          ? '<span class="decision suppress small">live 抑制</span>'
          : '<span class="badge">无 live 决定</span>';
      return `<li class="tl-item">
        <span class="tl-dot level-dot-${esc(a.level)}"></span>
        <span class="tl-seq">#${a.seq}</span>
        <span class="tl-ts">${esc(a.ts)}</span>
        ${levelBadge(a.level)}
        <span class="tl-msg">${esc(a.message || "")}</span>
        ${dec}
      </li>`;
    }).join("");
    return `<div class="event-card${ev.acknowledged ? " is-ack" : ""}">
      <div class="ev-head">
        <div class="ev-title">
          <b>${esc(ev.device_id || "(空设备)")}</b>
          <span class="badge">${esc(ev.alert_type || "(无类型)")}</span>
          ${levelBadge(ev.max_level)}<span class="hint" style="margin:0">最高级别</span>
          ${ack}
          ${ev.acked_at ? `<span class="hint" style="margin:0">确认于 ${esc(ev.acked_at)}</span>` : ""}
        </div>
        <div class="ev-actions">
          <button class="btn small" data-toggle-ev="${ev.id}" data-ack="${ev.acknowledged ? 0 : 1}">
            ${ev.acknowledged ? "取消确认" : "✓ 确认事件"}
          </button>
        </div>
      </div>
      <div class="ev-meta">
        <span>首条 <b>${esc(ev.first_ts)}</b></span>
        <span>末条 <b>${esc(ev.last_ts)}</b></span>
        <span>跨度 ${fmtDuration(dur)}</span>
        <span>告警数 <b>${ev.alert_count}</b></span>
        <span>聚合间隔 ${ev.gap_seconds}s</span>
      </div>
      <div class="ev-seqs">成员序号：${seqs}</div>
      <details class="ev-timeline">
        <summary>事件时间线（${ev.alert_count} 条，按告警时间排序）</summary>
        <ul class="tl-list">${timeline}</ul>
      </details>
    </div>`;
  }).join("");
}

async function saveGap() {
  const value = Number($("#ev-gap").value);
  try {
    const r = await api("/api/correlation/config", {
      method: "PUT", body: JSON.stringify({ gap_seconds: value }),
    });
    await loadEvents();
    const s = r.recompute;
    toast(`间隔已更新为 ${r.gap_seconds}s：新建 ${s.created} / 更新 ${s.updated} / 删除 ${s.deleted} 个事件`);
  } catch (e) { fail(e); }
}

async function recomputeEvents() {
  try {
    const s = await api("/api/events/recompute", { method: "POST" });
    await loadEvents();
    toast(`重算完成：共 ${s.events} 个事件（新建 ${s.created} / 更新 ${s.updated} / 删除 ${s.deleted}）`);
  } catch (e) { fail(e); }
}

async function toggleEventAck(id, ack) {
  try {
    await api(`/api/events/${id}/ack`, {
      method: "POST", body: JSON.stringify({ acknowledged: !!ack }),
    });
    await loadEvents();
  } catch (e) { fail(e); }
}

// ---------------------------------------------------------------------------
// Tab 2.5: 事件演进（快照 + 血缘对比）
// ---------------------------------------------------------------------------

const KIND_LABEL = {
  added: "新增",
  removed: "消失",
  continued: "延续",
  ack_changed: "确认变化",
  split: "拆分",
  merge: "合并",
  split_merge: "拆分+合并",
};

async function loadSnapshots() {
  state.snapshots = await api("/api/event-snapshots");
  renderSnapshots();
  renderSnapSelects();
}

function snapLabel(s) {
  const note = s.note ? ` · ${s.note}` : "";
  return `#${s.id} ${s.created_at} · ${s.event_count} 事件 · ${s.acknowledged_count} 已确认 · 间隔 ${s.gap_seconds}s${note}`;
}

function renderSnapshots() {
  $("#snap-total").textContent = `${state.snapshots.length} 个快照`;
  const box = $("#snapshot-list");
  if (!state.snapshots.length) {
    box.innerHTML = '<p class="empty">暂无快照。先注入告警生成事件，再点击上方按钮保存第一份快照。</p>';
    return;
  }
  box.innerHTML = state.snapshots.map((s) => `
    <div class="snapshot-item">
      <span><b>#${s.id}</b> ${esc(s.note || "(无说明)")}</span>
      <span style="color:var(--muted)">${esc(s.created_at)} · ${s.event_count} 事件 ·
        ${s.acknowledged_count} 已确认 · 间隔 ${s.gap_seconds}s</span>
    </div>`).join("");
}

function renderSnapSelects() {
  const from = $("#snap-from"), to = $("#snap-to");
  const opts = state.snapshots.map((s) =>
    `<option value="${s.id}">${esc(snapLabel(s))}</option>`).join("");
  from.innerHTML = opts;
  to.innerHTML = opts;
  const ids = state.snapshots.map((s) => s.id);
  // 默认对比最近两份快照；保留用户已选（若仍存在）
  if (!state.snapCompare.from || !ids.includes(state.snapCompare.from)) {
    state.snapCompare.from = ids.length >= 2 ? ids[ids.length - 2] : (ids[0] || null);
  }
  if (!state.snapCompare.to || !ids.includes(state.snapCompare.to)) {
    state.snapCompare.to = ids.length ? ids[ids.length - 1] : null;
  }
  if (state.snapCompare.from) from.value = state.snapCompare.from;
  if (state.snapCompare.to) to.value = state.snapCompare.to;
}

async function createSnapshot() {
  try {
    const s = await api("/api/event-snapshots", {
      method: "POST",
      body: JSON.stringify({ note: $("#snap-note").value.trim() }),
    });
    $("#snap-note").value = "";
    await loadSnapshots();
    toast(`快照 #${s.id} 已保存：${s.event_count} 个事件（间隔 ${s.gap_seconds}s），此后不再被改写`);
  } catch (e) { fail(e); }
}

async function compareSnapshots() {
  const from = Number($("#snap-from").value);
  const to = Number($("#snap-to").value);
  if (!from || !to) return toast("需要至少保存两份快照才能对比", true);
  state.snapCompare.from = from;
  state.snapCompare.to = to;
  try {
    state.snapCompare.result =
      await api(`/api/event-snapshots/compare?from_id=${from}&to_id=${to}`);
    renderSnapCompare();
  } catch (e) { fail(e); }
}

function snapEventHtml(ev) {
  const seqs = ev.member_seqs.map((s) => `<span class="seq-chip">#${s}</span>`).join(" ");
  const ack = ev.acknowledged
    ? '<span class="badge pass">✓ 已确认</span>'
    : '<span class="badge suppress">● 未确认</span>';
  return `<div class="rel-ev">
    <div class="rel-ev-head">
      <b>${esc(ev.device_id || "(空设备)")}</b>
      <span class="badge">${esc(ev.alert_type || "(无类型)")}</span>
      ${levelBadge(ev.max_level)} ${ack}
      <span class="hint" style="margin:0">事件ID ${ev.event_id}</span>
    </div>
    <div class="ev-meta">
      <span>首条 <b>${esc(ev.first_ts)}</b></span>
      <span>末条 <b>${esc(ev.last_ts)}</b></span>
      <span>告警数 <b>${ev.alert_count}</b></span>
    </div>
    <div class="ev-seqs">成员序号：${seqs}</div>
  </div>`;
}

function relationHtml(rel) {
  const badges = [`<span class="rel-kind kind-${rel.kind}">${KIND_LABEL[rel.kind]}</span>`];
  if (!rel.changed) badges.push('<span class="badge">未变化</span>');

  let inter;
  if (rel.old.length === 1 && rel.new.length === 1) {
    inter = `两侧交集 <b>${rel.intersection_count}</b> 条成员`;
  } else if (rel.intersections.length) {
    inter = `总交集 <b>${rel.intersection_count}</b> 条成员（逐对：` +
      rel.intersections.map((x) =>
        `旧E${x.old_event_id}∩新E${x.new_event_id}=${x.count}`).join("，") + "）";
  } else {
    inter = "两侧无交集成员";
  }

  const oldSide = rel.old.map(snapEventHtml).join("") ||
    '<p class="empty" style="padding:10px">（旧快照中无对应事件）</p>';
  const newSide = rel.new.map(snapEventHtml).join("") ||
    '<p class="empty" style="padding:10px">（新快照中无对应事件）</p>';
  return `<div class="relation-card${rel.changed ? "" : " unchanged"}">
    <div class="rel-head">${badges.join("")}<span class="rel-inter">${inter}</span></div>
    <div class="rel-sides">
      <div class="rel-side">
        <div class="rel-side-title">旧快照侧（${rel.old.length} 个事件）</div>${oldSide}
      </div>
      <div class="rel-arrow">→</div>
      <div class="rel-side">
        <div class="rel-side-title">新快照侧（${rel.new.length} 个事件）</div>${newSide}
      </div>
    </div>
  </div>`;
}

function renderSnapCompare() {
  const r = state.snapCompare.result;
  if (!r) return;
  const s = r.summary;
  $("#snap-summary").innerHTML =
    `对比 <b>#${r.from.id}${r.from.note ? ` ${esc(r.from.note)}` : ""}</b>（${esc(r.from.created_at)}）→
     <b>#${r.to.id}${r.to.note ? ` ${esc(r.to.note)}` : ""}</b>（${esc(r.to.created_at)}）：
     共 ${s.relations} 组血缘关系 — 新增 ${s.added} · 消失 ${s.removed} ·
     拆分 ${s.split} · 合并 ${s.merge} · 延续 ${s.continued} ·
     确认变化 ${s.ack_changed} · 未变化 ${s.unchanged}`;

  const onlyChanged = $("#snap-only-changed").checked;
  const rels = r.relations.filter((rel) => !onlyChanged || rel.changed);
  $("#snap-relations").innerHTML = rels.length
    ? rels.map(relationHtml).join("")
    : `<p class="empty">${onlyChanged ? "两个快照之间没有任何变化" : "两个快照都没有事件"}</p>`;
}

// ---------------------------------------------------------------------------
// Tab 3: 规则
// ---------------------------------------------------------------------------

function ruleMatches(r) {
  const dev = r.match_device || "*", batch = r.match_batch || "*", lvl = r.match_level || "*";
  const time = r.time_start ? `${r.time_start}-${r.time_end}` : "全天";
  const dates = (r.date_start || r.date_end)
    ? `${r.date_start || "…"} ~ ${r.date_end || "…"}` : "不限";
  return { dev, batch, lvl, time, dates };
}

function renderRules() {
  const tbody = $("#rules-body");
  if (!state.rules.length) {
    tbody.innerHTML = '<tr><td colspan="12" class="empty">暂无规则（无匹配时全部默认放行）</td></tr>';
    return;
  }
  const enabledOrdered = state.rules.filter((r) => r.enabled);
  const orderMap = new Map(enabledOrdered.map((r, i) => [r.id, i + 1]));
  tbody.innerHTML = state.rules.map((r) => {
    const m = ruleMatches(r);
    const order = r.enabled ? (orderMap.get(r.id) || "-") : "—";
    return `<tr${r.enabled ? "" : ' style="opacity:0.45"'}>
      <td>${order}</td>
      <td><b>${esc(r.name)}</b><br><span style="color:var(--muted);font-size:11.5px">${esc(r.description || "")}</span></td>
      <td>${r.action === "pass"
        ? '<span class="decision pass">pass</span>'
        : '<span class="decision suppress">suppress</span>'}</td>
      <td>${r.priority}</td>
      <td>${r.cooldown_seconds || "-"}</td>
      <td>${esc(m.dev)}</td>
      <td>${esc(m.batch)}</td>
      <td>${levelCell(m.lvl === "*" ? "" : m.lvl)}</td>
      <td>${esc(m.time)}</td>
      <td>${esc(m.dates)}</td>
      <td>${r.enabled ? '<span class="badge pass">启用</span>' : '<span class="badge suppress">停用</span>'}</td>
      <td style="white-space:nowrap">
        <button class="btn small" data-edit-rule="${r.id}">编辑</button>
        <button class="btn small" data-toggle-rule="${r.id}">${r.enabled ? "停用" : "启用"}</button>
        <button class="btn small danger" data-del-rule="${r.id}">删除</button>
      </td>
    </tr>`;
  }).join("");
}

function fillRuleForm(r) {
  $("#rule-id").value = r ? r.id : "";
  $("#form-title").textContent = r ? `编辑规则 #${r.id}` : "新建抑制规则";
  $("#f-name").value = r ? r.name : "";
  $("#f-desc").value = r ? r.description : "";
  $("#f-action").value = r ? r.action : "suppress";
  $("#f-priority").value = r ? r.priority : 100;
  $("#f-cooldown").value = r ? r.cooldown_seconds : 0;
  $("#f-device").value = r ? r.match_device : "";
  $("#f-batch").value = r ? r.match_batch : "";
  $("#f-level").value = r ? r.match_level : "";
  $("#f-time-start").value = r ? r.time_start : "";
  $("#f-time-end").value = r ? r.time_end : "";
  $("#f-date-start").value = r ? r.date_start : "";
  $("#f-date-end").value = r ? r.date_end : "";
  $("#f-enabled").checked = r ? !!r.enabled : true;
}

function collectRuleForm() {
  return {
    name: $("#f-name").value,
    description: $("#f-desc").value,
    action: $("#f-action").value,
    priority: Number($("#f-priority").value),
    cooldown_seconds: Number($("#f-cooldown").value),
    match_device: $("#f-device").value.trim(),
    match_batch: $("#f-batch").value.trim(),
    match_level: $("#f-level").value,
    time_start: $("#f-time-start").value.trim(),
    time_end: $("#f-time-end").value.trim(),
    date_start: $("#f-date-start").value,
    date_end: $("#f-date-end").value,
    enabled: $("#f-enabled").checked,
  };
}

async function saveRule() {
  const id = $("#rule-id").value;
  const body = collectRuleForm();
  try {
    await api(id ? `/api/rules/${id}` : "/api/rules", {
      method: id ? "PUT" : "POST",
      body: JSON.stringify(body),
    });
    fillRuleForm(null);
    await loadRules();
    renderRules();
    toast(id ? "规则已更新（提示：可到「策略对比」生成回放查看影响）" : "规则已创建");
  } catch (e) { fail(e); }
}

// ---------------------------------------------------------------------------
// Tab 4: 策略对比
// ---------------------------------------------------------------------------

function runLabel(r) {
  return `#${r.id} ${r.kind === "live" ? "[实时链]" : "[回放]"} ${r.note || ""} (${r.created_at}) — ${r.pass_count}放/${r.suppress_count}抑`;
}

function renderRunSelects() {
  const a = $("#cmp-a"), b = $("#cmp-b");
  const opts = state.runs.map((r) => `<option value="${r.id}">${esc(runLabel(r))}</option>`).join("");
  a.innerHTML = opts;
  b.innerHTML = opts;
  const live = state.runs.find((r) => r.kind === "live");
  const latestReplay = [...state.runs].reverse().find((r) => r.kind === "replay");
  state.compare.a = state.compare.a || (latestReplay ? latestReplay.id : live ? live.id : null);
  state.compare.b = state.compare.b || (live ? live.id : null);
  if (state.compare.a && state.runs.some((r) => r.id === state.compare.a)) a.value = state.compare.a;
  if (state.compare.b && state.runs.some((r) => r.id === state.compare.b)) b.value = state.compare.b;
  renderSnapshot();
}

async function doReplay() {
  try {
    const r = await api("/api/replays", {
      method: "POST",
      body: JSON.stringify({ note: $("#replay-note").value || "策略变更后回放" }),
    });
    $("#replay-note").value = "";
    await loadRuns();
    renderRunSelects();
    state.compare.a = r.id;
    $("#cmp-a").value = r.id;
    await loadCompare();
    toast(`已生成回放 #${r.id}，重放 ${r.replayed_alerts} 条告警`);
  } catch (e) { fail(e); }
}

async function loadCompare() {
  const a = Number($("#cmp-a").value);
  const b = Number($("#cmp-b").value);
  state.compare.a = a; state.compare.b = b;
  try {
    const result = await api(`/api/compare?run_a=${a}&run_b=${b}`);
    state.compare.result = result;
    renderCompare();
    renderSnapshot();
  } catch (e) { fail(e); }
}

function decisionCell(d) {
  if (!d) return '<span class="badge">无记录</span>';
  return `<span class="decision ${d.decision}">${d.decision === "pass" ? "放行" : "抑制"}</span>
          <div style="color:var(--muted);margin-top:3px;font-size:11.5px">
            ${d.rule_id ? `#${d.rule_id} ${esc(d.rule_name)}` : "默认策略"}</div>`;
}

function renderCompare() {
  const res = state.compare.result;
  if (!res) return;
  $("#cmp-summary").innerHTML =
    `对比 <b>${esc(res.run_a.note || res.run_a.kind)} (#${res.run_a.id})</b> 与
     <b>${esc(res.run_b.note || res.run_b.kind)} (#${res.run_b.id})</b><br>
     共 ${res.total} 条告警，<b style="color:var(--amber)">${res.changed_count} 条决定发生变化</b>`;
  $("#compare-body").innerHTML = res.rows.map((row) => {
    const a = row.alert;
    return `<tr class="${row.changed ? "row-changed" : ""}">
      <td>${a.seq}</td>
      <td>${esc(a.device_id || "-")}<br><span style="color:var(--muted)">${esc(a.batch_id || "-")}</span></td>
      <td>${levelBadge(a.level)}<br><span style="color:var(--muted)">${esc(a.alert_type || "-")}</span></td>
      <td style="white-space:nowrap">${esc(a.ts)}</td>
      <td>${decisionCell(row.a)}</td>
      <td class="reason-cell" style="max-width:280px;color:var(--muted);font-size:12px">${esc(row.a ? row.a.reason : "-")}</td>
      <td>${decisionCell(row.b)}</td>
      <td class="reason-cell" style="max-width:280px;color:var(--muted);font-size:12px">${esc(row.b ? row.b.reason : "-")}</td>
      <td>${row.changed
        ? '<span class="diff-mark">⇄ 已变化</span>'
        : '<span class="no-diff">一致</span>'}</td>
    </tr>`;
  }).join("") || '<tr><td colspan="9" class="empty">暂无已注入告警</td></tr>';
}

function renderSnapshot() {
  const a = state.runs.find((r) => r.id === Number($("#cmp-a")?.value));
  if (!a) return;
  $("#cmp-snapshot").innerHTML = (a.rule_snapshot || []).map((r) => {
    const m = ruleMatches(r);
    return `<div class="snap-rule">
      <div class="top">
        <b>#${r.id} ${esc(r.name)}</b>
        ${r.action === "pass" ? '<span class="decision pass">pass</span>' : '<span class="decision suppress">suppress</span>'}
        <span class="badge">优先级 ${r.priority}</span>
        ${r.cooldown_seconds ? `<span class="badge">冷却 ${r.cooldown_seconds}s</span>` : ""}
      </div>
      <div class="conds">设备 ${esc(m.dev)} · 批次 ${esc(m.batch)} · 级别 ${esc(m.lvl)} · 时段 ${esc(m.time)} · 日期 ${esc(m.dates)}</div>
    </div>`;
  }).join("") || '<p class="empty">无规则</p>';
}

// ---------------------------------------------------------------------------
// Tab 5: 模拟接收端
// ---------------------------------------------------------------------------

function renderSettings() {
  $("#set-forward").checked = state.settings.forward_enabled === "true";
  $("#set-mode").value = state.settings.receiver_mode || "mock";
  $("#set-url").value = state.settings.external_url || "";
}

async function saveSettings() {
  const body = {
    forward_enabled: $("#set-forward").checked,
    receiver_mode: $("#set-mode").value,
    external_url: $("#set-url").value.trim(),
  };
  try {
    state.settings = await api("/api/settings", { method: "PUT", body: JSON.stringify(body) });
    renderSettings();
    toast("设置已保存");
  } catch (e) { fail(e); }
}

async function loadReceiverLogs() {
  const logs = await api("/api/receiver/logs?limit=100");
  const box = $("#receiver-logs");
  if (!logs.length) {
    box.innerHTML = '<p class="empty">暂无投递记录。开启自动转发后注入放行告警，或手动发送测试包。</p>';
    return;
  }
  box.innerHTML = logs.map((l) => `
    <div class="log-item">
      <div class="top">
        <span><span class="status-${esc(l.status)}">● ${esc(l.status)}</span>
          ${l.alert_seq ? ` · 告警 #${l.alert_seq}` : ""} · ${esc(l.target)}</span>
        <span style="color:var(--muted)">${esc(l.created_at)}</span>
      </div>
      <div style="color:var(--muted);font-size:12px;margin-top:3px">${esc(l.detail)}</div>
      <pre>${esc(JSON.stringify(l.payload, null, 2))}</pre>
    </div>`).join("");
}

async function testMock() {
  try {
    await api("/mock-webhook", {
      method: "POST",
      body: JSON.stringify({ test: true, source: "sandbox-ui", at: new Date().toISOString() }),
    });
    await loadReceiverLogs();
    toast("测试包已送达内置接收端");
  } catch (e) { fail(e); }
}

// ---------------------------------------------------------------------------
// 示例数据 & 重置
// ---------------------------------------------------------------------------

const SAMPLE = [
  { device_id: "TR-01", batch_id: "B2026-09A", level: "warning", alert_type: "temp_high",
    message: "厢内温度 -15.2℃，高于阈值 -18℃", ts: "2026-09-21T00:05:00" },
  { device_id: "TR-01", batch_id: "B2026-09A", level: "critical", alert_type: "temp_high",
    message: "厢内温度 -9.0℃，存在断链风险", ts: "2026-09-21T00:15:00" },
  { device_id: "TR-01", batch_id: "B2026-09A", level: "warning", alert_type: "temp_high",
    message: "厢内温度 -16.4℃，夜间抖动", ts: "2026-09-21T00:30:00" },
  { device_id: "TR-02", batch_id: "B2026-09B", level: "warning", alert_type: "door_open",
    message: "后门开启超过 2 分钟", ts: "2026-09-21T00:45:00" },
  { device_id: "TR-02", batch_id: "B2026-09B", level: "warning", alert_type: "door_open",
    message: "后门仍未关闭", ts: "2026-09-21T00:47:00" },
  { device_id: "TR-02", batch_id: "B2026-09B", level: "warning", alert_type: "door_open",
    message: "后门仍未关闭（冷却窗内）", ts: "2026-09-21T00:52:00" },
  { device_id: "WH-03", batch_id: "B2026-09C", level: "info", alert_type: "sensor_offline",
    message: "冷库传感器心跳超时", ts: "2026-09-21T01:00:00" },
  { device_id: "TR-01", batch_id: "B2026-09A", level: "warning", alert_type: "temp_high",
    message: "厢内温度 -16.0℃，白天仍偏高（时段窗口外）", ts: "2026-09-21T09:00:00" },
];

// ---------------------------------------------------------------------------
// 事件绑定
// ---------------------------------------------------------------------------

document.addEventListener("click", async (e) => {
  const t = e.target;
  const ds = t.dataset;
  if (ds.toggleEv) {
    await toggleEventAck(Number(ds.toggleEv), Number(ds.ack));
  }
  if (ds.delStaged) {
    try { await api(`/api/staged/${ds.delStaged}`, { method: "DELETE" }); await loadStaged(); renderStaged(); }
    catch (err) { fail(err); }
  }
  if (ds.editRule) {
    const r = state.rules.find((x) => x.id === Number(ds.editRule));
    if (r) { fillRuleForm(r); window.scrollTo({ top: 0, behavior: "smooth" }); }
  }
  if (ds.toggleRule) {
    try { await api(`/api/rules/${ds.toggleRule}/toggle`, { method: "POST" }); await loadRules(); renderRules(); }
    catch (err) { fail(err); }
  }
  if (ds.delRule) {
    if (!confirm("确认删除该规则？")) return;
    try {
      await api(`/api/rules/${ds.delRule}`, { method: "DELETE" });
      if (Number($("#rule-id").value) === Number(ds.delRule)) fillRuleForm(null);
      await loadRules(); renderRules();
    } catch (err) { fail(err); }
  }
});

function bind() {
  document.querySelectorAll(".tab").forEach((btn) => btn.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".panel").forEach((p) => p.classList.remove("active"));
    btn.classList.add("active");
    $(`#tab-${btn.dataset.tab}`).classList.add("active");
    if (btn.dataset.tab === "receiver") loadReceiverLogs();
    if (btn.dataset.tab === "events") loadEvents().catch(fail);
    if (btn.dataset.tab === "evolution") loadSnapshots().catch(fail);
  }));

  $("#btn-inject-next").addEventListener("click", () => doInject(true));
  $("#btn-inject-all").addEventListener("click", () => doInject(false));
  $("#btn-undo").addEventListener("click", doUndo);
  $("#btn-save-gap").addEventListener("click", saveGap);
  $("#btn-recompute").addEventListener("click", recomputeEvents);
  $("#btn-snapshot").addEventListener("click", createSnapshot);
  $("#btn-compare-snap").addEventListener("click", compareSnapshots);
  $("#snap-only-changed").addEventListener("change", renderSnapCompare);
  $("#btn-clear-filters").addEventListener("click", async () => {
    for (const id of ["#ev-filter-device", "#ev-filter-level", "#ev-filter-status",
                      "#ev-filter-start", "#ev-filter-end"]) {
      $(id).value = "";
    }
    await loadEvents();
  });
  ["#ev-filter-device", "#ev-filter-level", "#ev-filter-status",
   "#ev-filter-start", "#ev-filter-end"].forEach((sel) =>
    $(sel).addEventListener("change", () => loadEvents().catch(fail)));
  $("#btn-import").addEventListener("click", () => doImport(false));
  $("#btn-import-append").addEventListener("click", () => doImport(true));
  $("#btn-direct-inject").addEventListener("click", doDirectInject);
  $("#btn-sample").addEventListener("click", () => {
    $("#import-json").value = JSON.stringify(SAMPLE, null, 2);
    toast("已填充 8 条内置示例，点击「导入（替换队列）」");
  });
  $("#btn-save-rule").addEventListener("click", saveRule);
  $("#btn-cancel-edit").addEventListener("click", () => fillRuleForm(null));
  $("#btn-replay").addEventListener("click", doReplay);
  $("#cmp-a").addEventListener("change", loadCompare);
  $("#cmp-b").addEventListener("change", loadCompare);
  $("#btn-save-settings").addEventListener("click", saveSettings);
  $("#btn-test-mock").addEventListener("click", testMock);
  $("#btn-clear-logs").addEventListener("click", async () => {
    try { await api("/api/receiver/clear", { method: "POST" }); await loadReceiverLogs(); toast("日志已清空"); }
    catch (err) { fail(err); }
  });
}

bind();
refreshAll().catch(fail);
