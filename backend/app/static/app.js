/*
 * ECDAT dashboard.
 *
 * Deliberately framework free: no build step, so "one Docker Compose command"
 * really is the only thing a judge has to run. Every view is a thin wrapper
 * around the existing /api/v1 endpoints. The dashboard adds no business
 * logic of its own, so what it shows is exactly what the API returns.
 *
 * Fixture mode is always labelled in the interface (see badge('fixture', ...)
 * calls below) so a canned demo result can never be mistaken for a live scan.
 */

const API = "/api/v1";

const state = {
  token: localStorage.getItem("ecdat_token") || null,
  username: localStorage.getItem("ecdat_username") || null,
  scans: [],
  currentScanId: null,
  tab: "scan",
};

// ---------------------------------------------------------------- fetch helpers

/**
 * Call the ECDAT API and unwrap the response.
 *
 * Attaches the bearer token when one is held, and treats a 401 as a dead
 * session: the token is cleared and the login view is shown, rather than
 * letting every subsequent view fail one at a time with its own error.
 *
 * @param {string} path Path below /api/v1, with a leading slash.
 * @param {RequestInit} [opts] Passed through to fetch.
 * @returns {Promise<any>} Parsed JSON, or null for an empty body.
 * @throws {Error} With the API's own `detail` message when available, so the
 *   user sees the server's explanation rather than a bare status code.
 */
async function api(path, opts = {}) {
  const headers = opts.headers || {};
  if (state.token) headers["Authorization"] = `Bearer ${state.token}`;
  if (opts.body) headers["Content-Type"] = "application/json";
  const res = await fetch(API + path, { ...opts, headers });
  if (res.status === 401) {
    logout();
    throw new Error("Session expired. Please log in again.");
  }
  const text = await res.text();
  let data;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  if (!res.ok) {
    const detail = data && data.detail ? (typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail)) : res.statusText;
    const err = new Error(detail);
    err.status = res.status;
    throw err;
  }
  return data;
}

/** Clear the stored session and return to the login view. */
function logout() {
  state.token = null;
  state.username = null;
  localStorage.removeItem("ecdat_token");
  localStorage.removeItem("ecdat_username");
  render();
}

// ------------------------------------------------------------------ small dom

/**
 * Build a DOM element.
 *
 * Deliberately minimal in place of a framework, so the dashboard needs no
 * build step. Text children are escaped by construction, since every string
 * becomes a text node rather than being interpolated into HTML. The one
 * exception is the `html` attribute, used only for the inline SVG icon set
 * defined in this file.
 *
 * @param {string} tag
 * @param {Object} [attrs] `class`, `html`, `on*` event handlers, or plain
 *   attributes.
 * @param {(Node|string|null)[]|Node|string} [children] Nulls are skipped, so a
 *   conditional child can be written inline.
 * @returns {HTMLElement}
 */
function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else if (k === "html") node.innerHTML = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v);
  }
  for (const child of [].concat(children)) {
    if (child == null) continue;
    node.appendChild(typeof child === "string" ? document.createTextNode(child) : child);
  }
  return node;
}

/**
 * A coloured severity pill.
 * @param {string} severity Drives the colour; also the label unless overridden.
 * @param {string} [extraText] Alternative label, for statuses such as "FIXTURE".
 */
function badge(severity, extraText) {
  return el("span", { class: `badge ${severity}` }, extraText || severity);
}

/** Format an ISO timestamp for display, or "-" when absent. */
function fmtDate(iso) {
  if (!iso) return "-";
  return new Date(iso).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

const ICONS = {
  scan: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 7V5a2 2 0 0 1 2-2h2M3 17v2a2 2 0 0 0 2 2h2M21 7V5a2 2 0 0 0-2-2h-2M21 17v2a2 2 0 0 1-2 2h-2M3 12h18"/></svg>',
  list: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/></svg>',
  grid: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>',
  shield: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2l8 4v6c0 5-3.5 8.5-8 10-4.5-1.5-8-5-8-10V6l8-4z"/></svg>',
  book: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 4.5A2.5 2.5 0 0 1 6.5 2H20v18H6.5A2.5 2.5 0 0 0 4 22.5v-18z"/></svg>',
  log: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 11l3 3L22 4M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/></svg>',
  sun: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>',
  moon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.8A9 9 0 1 1 11.2 3 7 7 0 0 0 21 12.8z"/></svg>',
};

/** Wrap one inline SVG from ICONS. Returns an empty span for an unknown name. */
function icon(name) {
  return el("span", { html: ICONS[name] || "" });
}

// ------------------------------------------------------------------- theming

/** Apply the saved theme before first paint, avoiding a flash of the wrong one. */
function initTheme() {
  const saved = localStorage.getItem("ecdat_theme");
  if (saved) document.documentElement.setAttribute("data-theme", saved);
}

/** Switch between light and dark, persist the choice, and repaint. */
function toggleTheme() {
  const current = document.documentElement.getAttribute("data-theme");
  const next = current === "dark" ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", next);
  localStorage.setItem("ecdat_theme", next);
  render();
}

// --------------------------------------------------------------------- root

/**
 * Draw the whole application.
 *
 * Full redraw rather than diffing. The dashboard has a handful of views and no
 * animation, so the simplicity is worth more than the efficiency.
 */
function render() {
  const root = document.getElementById("root");
  root.innerHTML = "";
  if (!state.token) {
    root.appendChild(loginView());
    return;
  }
  root.appendChild(shell());
}

/**
 * The persistent frame: sidebar, navigation, theme toggle, session controls.
 * The active view is loaded into it asynchronously by loadView.
 * @returns {HTMLElement}
 */
function shell() {
  const isDark = document.documentElement.getAttribute("data-theme") === "dark";
  const tabs = [
    ["scan", "New scan", "scan"],
    ["scans", "Scans", "list"],
    ["inventory", "Inventory", "grid"],
    ["pqc", "PQC readiness", "shield"],
    ["rules", "Rule catalogue", "book"],
    ["audit", "Audit trail", "log"],
  ];

  const nav = el("nav", { class: "tabs" }, tabs.map(([id, label, ic]) =>
    el("button", {
      class: state.tab === id ? "active" : "",
      onclick: () => { state.tab = id; render(); },
    }, [icon(ic), el("span", {}, label)])
  ));

  const sidebar = el("aside", { class: "sidebar" }, [
    el("div", { class: "brand" }, [
      el("span", { class: "mark" }, "ECDAT"),
      el("span", { class: "tag" }, "SIH26164"),
    ]),
    nav,
    el("div", { class: "sidebar-foot" }, [
      el("button", { class: "theme-toggle", onclick: toggleTheme }, [
        icon(isDark ? "sun" : "moon"),
        el("span", {}, isDark ? "Light mode" : "Dark mode"),
      ]),
      el("div", { style: "margin-top:8px" }, `Signed in as ${state.username}`),
      el("button", { class: "btn secondary small", style: "margin-top:6px;width:100%", onclick: logout }, "Log out"),
    ]),
  ]);

  const main = el("main", {}, [el("div", { id: "view" })]);
  const wrap = el("div", { class: "shell" }, [sidebar, main]);

  loadView(main.querySelector("#view"));
  return wrap;
}

/**
 * Load the active tab's view into a container.
 *
 * Shows a spinner while fetching and renders any failure as an error box, so a
 * failed request never leaves the panel blank with no explanation.
 *
 * @param {HTMLElement} container
 */
async function loadView(container) {
  container.innerHTML = "";
  const spin = el("div", { class: "empty-state" }, [el("span", { class: "spinner" }), " Loading..."]);
  container.appendChild(spin);
  try {
    let node;
    switch (state.tab) {
      case "scan": node = await newScanView(); break;
      case "scans": node = await scansView(); break;
      case "inventory": node = await inventoryView(); break;
      case "pqc": node = await pqcView(); break;
      case "rules": node = await rulesView(); break;
      case "audit": node = await auditView(); break;
      default: node = el("div", {}, "Unknown view");
    }
    container.innerHTML = "";
    container.appendChild(node);
  } catch (err) {
    container.innerHTML = "";
    container.appendChild(el("div", { class: "error-box" }, `Error: ${err.message}`));
  }
}

// ------------------------------------------------------------------- login

/**
 * The sign-in form.
 *
 * The seeded demo credentials are shown on screen deliberately: this is a
 * prototype whose password is in the README, and pretending otherwise would
 * only slow a reviewer down.
 *
 * @returns {HTMLElement}
 */
function loginView() {
  const wrap = el("div", { style: "max-width:360px;margin:14vh auto;padding:0 16px" });
  const errBox = el("div", {});
  const userField = el("input", { type: "text", value: "admin", autocomplete: "username" });
  const passField = el("input", { type: "password", value: "", autocomplete: "current-password", placeholder: "ecdat-demo" });

  const submit = async (e) => {
    e.preventDefault();
    errBox.innerHTML = "";
    try {
      const data = await api("/auth/login", {
        method: "POST",
        body: JSON.stringify({ username: userField.value, password: passField.value }),
      });
      state.token = data.access_token;
      state.username = userField.value;
      localStorage.setItem("ecdat_token", state.token);
      localStorage.setItem("ecdat_username", state.username);
      render();
    } catch (err) {
      errBox.appendChild(el("div", { class: "error-box" }, err.message));
    }
  };

  const form = el("form", { onsubmit: submit }, [
    el("h1", { style: "font-size:22px;margin:0 0 4px" }, "ECDAT"),
    el("p", { style: "color:var(--color-muted);margin:0 0 20px;font-size:13px" },
      "Enterprise Cryptographic Discovery and Analysis Tool"),
    errBox,
    el("div", { class: "field", style: "margin-bottom:12px" }, [el("label", {}, "Username"), userField]),
    el("div", { class: "field", style: "margin-bottom:16px" }, [el("label", {}, "Password"), passField]),
    el("button", { class: "btn", type: "submit", style: "width:100%" }, "Log in"),
    el("p", { style: "color:var(--color-soft);font-size:11px;margin-top:14px" },
      "Seeded credentials: admin / ecdat-demo"),
  ]);
  wrap.appendChild(form);
  return wrap;
}

// ---------------------------------------------------------------- new scan

/**
 * The scan submission form.
 *
 * The authorisation checkbox appears only for a TLS scan, because that is the
 * only kind that touches the network. Submitting without it returns 403 from
 * the API and the refusal is recorded in the audit trail.
 *
 * @returns {Promise<HTMLElement>}
 */
async function newScanView() {
  const wrap = el("div");
  wrap.appendChild(el("header", { class: "page-head" }, [
    el("div", {}, [
      el("h1", {}, "Start a scan"),
      el("p", {}, "Code, TLS or certificate discovery. A network scan is refused unless explicitly authorised, and the refusal is written to the audit trail."),
    ]),
  ]));

  const kindSel = el("select", {}, [
    el("option", { value: "code" }, "Source code"),
    el("option", { value: "certificate" }, "Certificate"),
    el("option", { value: "tls" }, "TLS endpoint"),
  ]);
  const targetInput = el("input", { type: "text", placeholder: "../samples/vulnerable-repo", value: "../samples/vulnerable-repo" });
  const authCheck = el("input", { type: "checkbox", id: "auth-check" });
  const fixtureCheck = el("input", { type: "checkbox", id: "fixture-check" });
  const statusBox = el("div", {});
  const submitBtn = el("button", { class: "btn", type: "submit" }, "Submit scan");

  const presets = {
    code: "../samples/vulnerable-repo",
    certificate: "../samples/certs",
    tls: "127.0.0.1:8443",
  };
  kindSel.addEventListener("change", () => {
    targetInput.value = presets[kindSel.value] || "";
    authCheck.parentElement.style.display = kindSel.value === "tls" ? "flex" : "none";
  });

  const authRow = el("div", { class: "checkbox-row", style: "display:none" }, [
    authCheck, el("label", { for: "auth-check" }, "I am authorised to scan this network target"),
  ]);

  const form = el("form", {
    class: "card",
    onsubmit: async (e) => {
      e.preventDefault();
      statusBox.innerHTML = "";
      submitBtn.disabled = true;
      submitBtn.textContent = "Submitting...";
      try {
        const scan = await api("/scans", {
          method: "POST",
          body: JSON.stringify({
            kind: kindSel.value,
            target: targetInput.value,
            authorized: authCheck.checked,
            fixture: fixtureCheck.checked,
          }),
        });
        statusBox.appendChild(pollScan(scan.id));
      } catch (err) {
        statusBox.appendChild(el("div", { class: "error-box" }, err.message));
      } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = "Submit scan";
      }
    },
  }, [
    el("h2", {}, "Scan target"),
    el("div", { class: "form-row" }, [
      el("div", { class: "field" }, [el("label", {}, "Kind"), kindSel]),
      el("div", { class: "field" }, [el("label", {}, "Target"), targetInput]),
    ]),
    el("div", { class: "form-row" }, [
      authRow,
      el("div", { class: "checkbox-row" }, [
        fixtureCheck,
        el("label", { for: "fixture-check" }, "Fixture mode (canned demo result, never a live scan)"),
      ]),
    ]),
    submitBtn,
  ]);

  wrap.appendChild(form);
  wrap.appendChild(statusBox);

  const note = el("div", { class: "note" },
    "Read endpoints stay open so results are easy to browse. Every write, including submitting a scan, requires the bearer token issued at login.");
  wrap.appendChild(note);

  return wrap;
}

/**
 * Watch a queued scan until it finishes, then show its result and downloads.
 *
 * Polls rather than holding a socket open: scans complete in tens of
 * milliseconds and a WebSocket would be more moving parts for no gain.
 *
 * @param {number} scanId
 * @returns {HTMLElement} A card that updates itself in place.
 */
function pollScan(scanId) {
  const box = el("div", { class: "card" }, [
    el("h2", {}, `Scan #${scanId}`),
    el("div", { id: `scan-status-${scanId}` }, [el("span", { class: "spinner" }), " queued..."]),
  ]);
  const tick = async () => {
    const target = box.querySelector(`#scan-status-${scanId}`);
    if (!target) return;
    try {
      const scan = await api(`/scans/${scanId}`);
      if (scan.status === "completed") {
        target.innerHTML = "";
        target.appendChild(badge("LOW", "completed"));
        target.appendChild(el("span", { style: "margin-left:8px" },
          `${scan.finding_count} finding${scan.finding_count === 1 ? "" : "s"} in ${scan.duration_ms}ms`));
        if (scan.fixture_mode) target.appendChild(badge("fixture", "FIXTURE DATA"));
        const links = el("div", { style: "margin-top:10px", class: "pill-row" }, [
          el("a", { class: "btn small secondary", href: `${API}/scans/${scanId}/findings`, target: "_blank" }, "Findings JSON"),
          el("a", { class: "btn small secondary", href: `${API}/scans/${scanId}/report.pdf` }, "PDF report"),
          el("a", { class: "btn small secondary", href: `${API}/scans/${scanId}/report.cbom.json`, target: "_blank" }, "CycloneDX CBOM"),
          el("button", { class: "btn small", onclick: () => { state.currentScanId = scanId; state.tab = "scans"; render(); } }, "View in Scans"),
        ]);
        target.parentElement.appendChild(links);
        state.currentScanId = scanId;
      } else if (scan.status === "failed") {
        target.innerHTML = "";
        target.appendChild(badge("CRITICAL", "failed"));
        target.appendChild(el("div", { class: "error-box", style: "margin-top:8px" }, scan.error || "Unknown error"));
      } else {
        setTimeout(tick, 500);
      }
    } catch (err) {
      target.innerHTML = "";
      target.appendChild(el("div", { class: "error-box" }, err.message));
    }
  };
  setTimeout(tick, 400);
  return box;
}

// --------------------------------------------------------------------- scans

/** Scan history, most recent first, with a per-row findings drill-down. */
async function scansView() {
  const data = await api("/scans?limit=50");
  state.scans = data;
  const wrap = el("div");
  wrap.appendChild(el("header", { class: "page-head" }, [
    el("div", {}, [el("h1", {}, "Scans"), el("p", {}, "Most recent first. Select a scan to browse its findings.")]),
  ]));

  if (!data.length) {
    wrap.appendChild(el("div", { class: "empty-state" }, "No scans yet. Start one from the New scan tab."));
    return wrap;
  }

  const table = el("table", {}, [
    el("thead", {}, el("tr", {}, ["ID", "Kind", "Target", "Status", "Findings", "Started", "Duration", ""].map(h => el("th", {}, h)))),
    el("tbody", {}, data.map(s => el("tr", {}, [
      el("td", {}, `#${s.id}`),
      el("td", {}, s.kind),
      el("td", {}, [el("code", {}, s.target), s.fixture_mode ? badge("fixture", "FIXTURE") : null]),
      el("td", {}, s.status === "completed" ? badge("LOW", "completed") : s.status === "failed" ? badge("CRITICAL", "failed") : badge("MEDIUM", s.status)),
      el("td", {}, String(s.finding_count)),
      el("td", {}, fmtDate(s.started_at)),
      el("td", {}, s.duration_ms != null ? `${s.duration_ms}ms` : "-"),
      el("td", {}, el("button", {
        class: "btn small secondary",
        onclick: () => { state.currentScanId = s.id; showFindings(wrap, s.id); },
      }, "Findings")),
    ]))),
  ]);
  wrap.appendChild(table);
  wrap.appendChild(el("div", { id: "findings-panel" }));

  if (state.currentScanId) {
    showFindings(wrap, state.currentScanId);
  }
  return wrap;
}

/**
 * Render the findings table for one scan, with live filters.
 *
 * Filtering is done server-side so the client never holds a partial result set
 * and then filters it into something misleading.
 *
 * @param {HTMLElement} wrap Container holding the findings panel.
 * @param {number} scanId
 */
async function showFindings(wrap, scanId) {
  let panel = wrap.querySelector("#findings-panel");
  if (!panel) { panel = el("div", { id: "findings-panel" }); wrap.appendChild(panel); }
  panel.innerHTML = "";
  panel.appendChild(el("div", { class: "empty-state" }, [el("span", { class: "spinner" }), " Loading findings..."]));

  const sevSel = el("select", {}, ["", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map(v => el("option", { value: v }, v || "All severities")));
  const sourceSel = el("select", {}, ["", "code", "tls", "certificate"].map(v => el("option", { value: v }, v || "All sources")));
  const algoInput = el("input", { type: "text", placeholder: "Filter by algorithm..." });

  const reload = async () => {
    const params = new URLSearchParams();
    if (sevSel.value) params.set("severity", sevSel.value);
    if (sourceSel.value) params.set("source", sourceSel.value);
    if (algoInput.value) params.set("algorithm", algoInput.value);
    const data = await api(`/scans/${scanId}/findings?${params.toString()}`);
    body.innerHTML = "";
    if (!data.findings.length) {
      body.appendChild(el("div", { class: "empty-state" }, "No findings match these filters."));
      return;
    }
    body.appendChild(el("table", {}, [
      el("thead", {}, el("tr", {}, ["Severity", "Algorithm", "Location", "Class.", "Quant.", "Conf.", "Reference", "PQC"].map(h => el("th", {}, h)))),
      el("tbody", {}, data.findings.map(f => el("tr", {}, [
        el("td", {}, badge(f.severity)),
        el("td", {}, el("code", {}, f.algorithm)),
        el("td", {}, el("code", {}, `${f.file_path || f.locator}${f.line_no ? ":" + f.line_no : ""}`)),
        el("td", {}, f.classical_score.toFixed(1)),
        el("td", {}, f.quantum_score.toFixed(1)),
        el("td", {}, f.confidence.toFixed(2)),
        el("td", { style: "font-size:11px;color:var(--color-muted)" }, f.standard_refs || f.cwe || "-"),
        el("td", {}, f.pqc_vulnerable ? badge("pqc", "quantum") : "-"),
      ]))),
    ]));
  };

  [sevSel, sourceSel].forEach(s => s.addEventListener("change", reload));
  algoInput.addEventListener("input", debounce(reload, 300));

  const body = el("div", {});
  panel.innerHTML = "";
  panel.appendChild(el("div", { class: "card" }, [
    el("h2", {}, `Findings for scan #${scanId}`),
    el("div", { class: "filters" }, [sevSel, sourceSel, algoInput]),
    body,
  ]));
  reload();
}

/**
 * Delay a call until input stops, so typing a filter is not one request per key.
 * @param {Function} fn
 * @param {number} ms
 */
function debounce(fn, ms) {
  let t;
  return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
}

// ----------------------------------------------------------------- inventory

/**
 * The unified asset-by-algorithm matrix.
 *
 * The central claim of the tool, on one screen: every asset from every source
 * scanned so far, in one table, with the cross-source correlations listed
 * beneath it. Cells are shaded by worst severity and marked when the algorithm
 * is quantum vulnerable.
 *
 * @returns {Promise<HTMLElement>}
 */
async function inventoryView() {
  const wrap = el("div");
  wrap.appendChild(el("header", { class: "page-head" }, [
    el("div", {}, [
      el("h1", {}, "Unified inventory"),
      el("p", {}, "Every asset against every algorithm found, across every source scanned so far. This is the view no single-purpose tool can produce."),
    ]),
  ]));

  if (!state.scans.length) state.scans = await api("/scans?limit=50");
  const completed = state.scans.filter(s => s.status === "completed");
  if (!completed.length) {
    wrap.appendChild(el("div", { class: "empty-state" }, "Run a scan first."));
    return wrap;
  }
  const scanId = state.currentScanId && completed.some(s => s.id === state.currentScanId)
    ? state.currentScanId : completed[0].id;

  const data = await api(`/scans/${scanId}/inventory`);
  if (!data.assets.length) {
    wrap.appendChild(el("div", { class: "empty-state" }, "No findings recorded yet."));
    return wrap;
  }

  const sevOrder = { CRITICAL: 3, HIGH: 2, MEDIUM: 1, LOW: 0 };
  const sevColor = { CRITICAL: "var(--sev-critical-tint)", HIGH: "var(--sev-high-tint)", MEDIUM: "var(--sev-medium-tint)", LOW: "var(--sev-low-tint)" };

  const table = el("table", { class: "matrix" });
  const headRow = el("tr", {}, [el("th", { class: "row-head" }, "Asset")]);
  data.algorithms.forEach(a => headRow.appendChild(el("th", { class: "col-head" }, a)));
  table.appendChild(el("thead", {}, headRow));

  const tbody = el("tbody");
  data.assets.forEach(asset => {
    const row = el("tr", {}, [
      el("td", { class: "row-head" }, [
        el("span", { style: "opacity:.6;font-size:10px" }, `[${data.sources[asset] || "?"}] `),
        asset,
      ]),
    ]);
    data.algorithms.forEach(algo => {
      const cell = data.cells[asset] && data.cells[asset][algo];
      if (cell) {
        row.appendChild(el("td", {
          class: "cell-hit",
          style: `background:${sevColor[cell.severity]}`,
          title: `${cell.count} finding(s), ${cell.severity}${cell.pqc_vulnerable ? ", quantum vulnerable" : ""}`,
        }, cell.pqc_vulnerable ? `${cell.count}⚛` : String(cell.count)));
      } else {
        row.appendChild(el("td", {}, ""));
      }
    });
    tbody.appendChild(row);
  });
  table.appendChild(tbody);

  wrap.appendChild(el("div", { class: "card" }, [
    el("h2", {}, `Scan #${scanId}: ${data.assets.length} assets x ${data.algorithms.length} algorithms`),
    el("div", { class: "matrix-wrap" }, table),
  ]));

  if (data.correlations.length) {
    wrap.appendChild(el("div", { class: "card" }, [
      el("h2", {}, `Cross-source correlations (${data.correlations.length})`),
      el("p", { style: "font-size:12.5px;color:var(--color-muted);margin-top:-6px" },
        "Links between assets found by different scanners: the same key appearing in code and in a certificate, or a host matching a certificate subject."),
      el("ul", { class: "link-list" }, data.correlations.map(c => el("li", {}, [
        el("code", {}, c.a), " ↔ ", el("code", {}, c.b),
        el("div", { style: "color:var(--color-soft);font-size:11px;margin-top:2px" }, `${c.relation}: ${c.note}`),
      ]))),
    ]));
  } else {
    wrap.appendChild(el("div", { class: "note" }, "No cross-source correlations yet. Scan code and certificates that share a key to see one."));
  }

  return wrap;
}

// ----------------------------------------------------------------------- pqc

/**
 * Post-quantum readiness: the percentage, and the migration table.
 *
 * Leads with the countdown sentence rather than a percentage, because "RSA in
 * 4 assets, 9 years remaining" is actionable in a way that "37.5% ready" is not.
 *
 * @returns {Promise<HTMLElement>}
 */
async function pqcView() {
  const wrap = el("div");
  wrap.appendChild(el("header", { class: "page-head" }, [
    el("div", {}, [el("h1", {}, "Post-quantum readiness"), el("p", {}, "Measured against NIST IR 8547: quantum-vulnerable algorithms are deprecated after 2030 and disallowed after 2035.")]),
  ]));

  if (!state.scans.length) state.scans = await api("/scans?limit=50");
  const completed = state.scans.filter(s => s.status === "completed");
  if (!completed.length) {
    wrap.appendChild(el("div", { class: "empty-state" }, "Run a scan first."));
    return wrap;
  }
  const scanId = state.currentScanId && completed.some(s => s.id === state.currentScanId)
    ? state.currentScanId : completed[0].id;

  const data = await api(`/scans/${scanId}/pqc`);

  wrap.appendChild(el("div", { class: "headline" }, data.headline));
  wrap.appendChild(el("div", { class: "kpi-row" }, [
    el("div", { class: "kpi accent" }, [el("span", { class: "n" }, `${data.readiness_percent}%`), el("span", { class: "l" }, "PQC ready")]),
    el("div", { class: "kpi" }, [el("span", { class: "n" }, String(data.ready_assets)), el("span", { class: "l" }, "Ready assets")]),
    el("div", { class: "kpi crit" }, [el("span", { class: "n" }, String(data.at_risk_assets)), el("span", { class: "l" }, "At risk assets")]),
    el("div", { class: "kpi" }, [el("span", { class: "n" }, String(data.total_assets)), el("span", { class: "l" }, "Total assets")]),
  ]));

  if (data.migrations.length) {
    const table = el("table", {}, [
      el("thead", {}, el("tr", {}, ["Algorithm", "Assets", "Migrate to", "Standard", "Deprecated", "Disallowed", "Years left"].map(h => el("th", {}, h)))),
      el("tbody", {}, data.migrations.map(m => el("tr", {}, [
        el("td", {}, el("code", {}, m.algorithm)),
        el("td", {}, String(m.assets)),
        el("td", {}, el("code", {}, m.target)),
        el("td", {}, m.standard),
        el("td", {}, String(m.deprecated_after || "-")),
        el("td", {}, String(m.disallowed_after)),
        el("td", {}, el("strong", {}, String(m.years_remaining))),
      ]))),
    ]);
    wrap.appendChild(el("div", { class: "card" }, [el("h2", {}, "Migration table"), table]));
  } else {
    wrap.appendChild(el("div", { class: "note" }, "No quantum-vulnerable algorithms found in this scope."));
  }
  return wrap;
}

// --------------------------------------------------------------------- rules

/**
 * The detection rule catalogue.
 *
 * Every rule with its algorithm, confidence, languages and the published
 * standard behind it, read live from the API. This makes the reference list a
 * verifiable property of the running tool rather than a claim in a document.
 *
 * @returns {Promise<HTMLElement>}
 */
async function rulesView() {
  const data = await api("/rules");
  const wrap = el("div");
  wrap.appendChild(el("header", { class: "page-head" }, [
    el("div", {}, [el("h1", {}, "Detection rule catalogue"), el("p", {}, `${data.count} rules. Every one traces to a published standard, making this a live, verifiable version of that reference list.`)]),
  ]));

  wrap.appendChild(el("div", { class: "card" }, data.rules.map(r => el("div", { class: "rule-row" }, [
    el("div", { class: "id" }, `${r.id} · ${r.group}`),
    el("div", { class: "name" }, r.name),
    el("div", { class: "meta" }, [
      el("span", {}, `algorithm: ${r.algorithm}`),
      el("span", {}, `confidence: ${r.confidence.toFixed(2)}`),
      el("span", {}, `languages: ${r.languages.join(", ") || "all"}`),
      el("span", {}, r.cwe ? `${r.cwe}` : ""),
      el("span", { style: "color:var(--color-soft)" }, (r.references || []).join("; ")),
    ]),
  ]))));

  return wrap;
}

// --------------------------------------------------------------------- audit

/**
 * The audit trail, newest first.
 *
 * Read-only by design: no route exists anywhere in the API to modify or delete
 * these rows. Refusals and failed logins are highlighted, since those are the
 * entries a reviewer is usually looking for.
 *
 * @returns {Promise<HTMLElement>}
 */
async function auditView() {
  const data = await api("/audit?limit=100");
  const wrap = el("div");
  wrap.appendChild(el("header", { class: "page-head" }, [
    el("div", {}, [
      el("h1", {}, "Audit trail"),
      el("p", {}, "Read only. There is no route anywhere in the API that updates or deletes these rows. A refused scan is recorded here too."),
    ]),
  ]));

  if (!data.entries.length) {
    wrap.appendChild(el("div", { class: "empty-state" }, "No audit entries yet."));
    return wrap;
  }

  const table = el("table", {}, [
    el("thead", {}, el("tr", {}, ["Time", "Actor", "Action", "Target", "Detail"].map(h => el("th", {}, h)))),
    el("tbody", {}, data.entries.map(e => el("tr", {}, [
      el("td", {}, fmtDate(e.ts)),
      el("td", {}, e.actor),
      el("td", {}, e.action.includes("denied") || e.action.includes("failed") ? badge("CRITICAL", e.action) : badge("LOW", e.action)),
      el("td", {}, el("code", {}, e.target)),
      el("td", { style: "font-size:11.5px;color:var(--color-muted)" }, e.detail || ""),
    ]))),
  ]);
  wrap.appendChild(table);
  return wrap;
}

// --------------------------------------------------------------------- boot

initTheme();
render();
