import { html, useState, useEffect } from "../app.js";
import { navigate } from "../app.js";
import { getMe, loginUrl, logout } from "../api.js";

let _authState = null;
let _listeners = [];
function subscribeAuth(fn) { _listeners.push(fn); return () => { _listeners = _listeners.filter(l => l !== fn); }; }
function notifyAuth(user) { _authState = user; _listeners.forEach(fn => fn(user)); }

export async function initAuth() {
  const user = await getMe();
  notifyAuth(user);
  return user;
}

export function Header({ currentPath }) {
  const [user, setUser] = useState(_authState);

  useEffect(() => subscribeAuth(setUser), []);

  const handleLogout = async () => {
    await logout();
    notifyAuth(null);
    navigate("/");
  };

  const navLink = (href, label) => {
    const active = currentPath === href || (href !== "/" && currentPath.startsWith(href + "/"));
    return html`<a
      href="${href}"
      class="${active ? "active" : ""}"
      onClick=${(e) => { e.preventDefault(); navigate(href); }}
    >${label}</a>`;
  };

  return html`
    <header class="header">
      <div class="header-inner">
        <a href="/" class="logo" style="text-decoration:none"
           onClick=${(e) => { e.preventDefault(); navigate("/"); }}>
          <span class="logo-icon">🔍</span>
          <span>PoC Hunter</span>
        </a>
        <nav>
          ${navLink("/", "Dashboard")}
          ${navLink("/findings", "Findings")}
          ${navLink("/scan-runs", "Scan History")}
          ${navLink("/about", "About")}
        </nav>
        <div class="auth-btn">
          ${user
            ? html`
                <img src="${user.github_avatar_url || ""}" alt="${user.github_user}" class="user-avatar" />
                <span class="text-muted">${user.github_user}</span>
                <button class="btn btn-ghost btn-sm" onClick=${handleLogout}>Logout</button>
              `
            : html`
                <a href="${loginUrl()}" class="btn btn-ghost btn-sm">Login</a>
              `
          }
        </div>
      </div>
    </header>
  `;
}
