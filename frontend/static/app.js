/**
 * Malicious PoC Hunter – Main SPA entry point.
 * Uses Preact + HTM (no build step). All imports are ES modules.
 */
import { h, render, createContext } from "https://esm.sh/preact@10.25.3";
import { useState, useEffect, useRef, useContext, useCallback } from "https://esm.sh/preact@10.25.3/hooks";
import htm from "https://esm.sh/htm@3.1.1";

// Bind htm to Preact's h
const html = htm.bind(h);

// Re-export hooks + html so component files can import from app.js
export { html, h, useState, useEffect, useRef, useContext, useCallback };

// ---- Minimal client-side router ---- //

let _routeListeners = [];
let _currentPath = window.location.pathname;

export function navigate(path) {
  window.history.pushState(null, "", path);
  _currentPath = path;
  _routeListeners.forEach(fn => fn(path));
}

window.addEventListener("popstate", () => {
  _currentPath = window.location.pathname;
  _routeListeners.forEach(fn => fn(_currentPath));
});

function useRouter() {
  const [path, setPath] = useState(window.location.pathname);
  useEffect(() => {
    const fn = p => setPath(p);
    _routeListeners.push(fn);
    return () => { _routeListeners = _routeListeners.filter(l => l !== fn); };
  }, []);
  return path;
}

// ---- Toast notifications ---- //

let _setToastsGlobal = null;

export function toast(msg, type = "info") {
  if (_setToastsGlobal) {
    const id = Date.now();
    _setToastsGlobal(prev => [...prev, { id, msg, type }]);
    setTimeout(() => _setToastsGlobal(prev => prev.filter(t => t.id !== id)), 4000);
  }
}

function ToastContainer() {
  const [toasts, setToasts] = useState([]);
  useEffect(() => { _setToastsGlobal = setToasts; return () => { _setToastsGlobal = null; }; }, []);
  return html`
    <div class="toast-container">
      ${toasts.map(t => html`<div key=${t.id} class="toast ${t.type}">${t.msg}</div>`)}
    </div>
  `;
}

// Register toast with api module
import { registerToast } from "./api.js";
registerToast(toast);

// ---- Lazy component imports ---- //
import { Header, initAuth } from "./components/header.js";
import { DashboardPage }    from "./components/dashboard.js";
import { FindingsListPage } from "./components/findings-list.js";
import { FindingDetailPage } from "./components/finding-detail.js";
import { ScanRunsPage }     from "./components/scan-runs.js";
import { AboutPage }        from "./components/about.js";

// ---- Route matching ---- //

function matchRoute(path) {
  if (path === "/" || path === "") return { page: "dashboard" };
  if (path === "/findings")        return { page: "findings" };
  if (path.startsWith("/findings/")) {
    const id = parseInt(path.split("/")[2]);
    if (!isNaN(id)) return { page: "finding-detail", id };
  }
  if (path === "/scan-runs")       return { page: "scan-runs" };
  if (path === "/about")           return { page: "about" };
  return { page: "not-found" };
}

// ---- Root App component ---- //

function App() {
  const path = useRouter();
  const [user, setUser] = useState(null);
  const route = matchRoute(path);

  useEffect(() => {
    initAuth().then(u => setUser(u));
  }, []);

  let pageContent;
  switch (route.page) {
    case "dashboard":       pageContent = html`<${DashboardPage} />`; break;
    case "findings":        pageContent = html`<${FindingsListPage} />`; break;
    case "finding-detail":  pageContent = html`<${FindingDetailPage} id=${route.id} user=${user} />`; break;
    case "scan-runs":       pageContent = html`<${ScanRunsPage} />`; break;
    case "about":           pageContent = html`<${AboutPage} />`; break;
    default:
      pageContent = html`<div class="container error-msg mt-3">404 – Page not found.</div>`;
  }

  return html`
    <div class="app-layout">
      <${Header} currentPath=${path} />
      <main>${pageContent}</main>
      <footer>
        <div>
          Malicious PoC Hunter · Automated security research protection ·
          <a href="https://github.com/DONKEY0xSHOT/Malicious-Poc-Hunter" target="_blank" rel="noopener noreferrer">GitHub</a>
        </div>
      </footer>
      <${ToastContainer} />
    </div>
  `;
}

render(html`<${App} />`, document.getElementById("app"));
