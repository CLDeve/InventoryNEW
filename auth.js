const InventoryAuth = (() => {
  const TOKEN_KEY = "inventoryToken";
  const API_BASE = "";

  function normalizeUpper(value) {
    return String(value || "").trim().toUpperCase();
  }

  function tokenGet() {
    return localStorage.getItem(TOKEN_KEY) || "";
  }

  function tokenSet(token) {
    localStorage.setItem(TOKEN_KEY, token);
  }

  function tokenClear() {
    localStorage.removeItem(TOKEN_KEY);
  }

  function decodeTokenPayload(token) {
    if (!token) return null;
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    try {
      const payload = JSON.parse(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")));
      return payload;
    } catch (err) {
      return null;
    }
  }

  function getCurrentUser() {
    const payload = decodeTokenPayload(tokenGet());
    if (!payload || !payload.username || !payload.rights) return null;
    const nowSec = Math.floor(Date.now() / 1000);
    if (payload.exp && Number(payload.exp) < nowSec) {
      tokenClear();
      return null;
    }
    return {
      id: payload.sub,
      username: payload.username,
      fullName: payload.fullName || payload.username,
      rights: payload.rights,
      canLogin: true
    };
  }

  function hasRight(user, rightKey) {
    return Boolean(user && user.rights && user.rights[rightKey]);
  }

  function firstAllowedPage(user) {
    if (!user) return "login-page.html";
    if (hasRight(user, "deviceMaster")) return "device-master-page.html";
    if (hasRight(user, "userSetup")) return "user-setup-page.html";
    if (hasRight(user, "actionLog")) return "action-log-page.html";
    if (hasRight(user, "userManagement")) return "user-management-page.html";
    return "login-page.html";
  }

  async function apiRequest(path, options = {}) {
    const headers = {
      "Content-Type": "application/json",
      ...(options.headers || {})
    };

    const token = tokenGet();
    if (token && !headers.Authorization) {
      headers.Authorization = `Bearer ${token}`;
    }

    const response = await fetch(`${API_BASE}${path}`, {
      method: options.method || "GET",
      headers,
      body: options.body ? JSON.stringify(options.body) : undefined
    });

    let data = null;
    try {
      data = await response.json();
    } catch (err) {
      data = null;
    }

    if (!response.ok) {
      const message = (data && data.message) || `Request failed: ${response.status}`;
      const error = new Error(message);
      error.status = response.status;
      error.payload = data;
      throw error;
    }

    return data || {};
  }

  async function login(username, password) {
    const normalizedUsername = normalizeUpper(username);
    const normalizedPassword = normalizeUpper(password);
    if (!normalizedUsername || !normalizedPassword) {
      return { ok: false, message: "USERNAME AND PASSWORD ARE REQUIRED." };
    }

    try {
      const data = await apiRequest("/api/auth/login", {
        method: "POST",
        body: {
          username: normalizedUsername,
          password: normalizedPassword
        }
      });

      if (!data.token) {
        return { ok: false, message: "LOGIN FAILED." };
      }

      tokenSet(data.token);
      const user = data.user || getCurrentUser();
      return {
        ok: true,
        user,
        redirect: firstAllowedPage(user)
      };
    } catch (err) {
      return { ok: false, message: err.message || "LOGIN FAILED." };
    }
  }

  function logout() {
    const user = getCurrentUser();
    const token = tokenGet();
    tokenClear();
    if (user && token) {
      fetch("/api/auth/logout", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`
        }
      }).catch(() => {
        // Ignore logout request failures.
      });
    }
    window.location.replace("login-page.html");
  }

  function requireAuth(requiredRight) {
    const user = getCurrentUser();
    if (!user) {
      window.location.href = "login-page.html";
      return null;
    }

    if (requiredRight && !hasRight(user, requiredRight)) {
      addActionLog("SYSTEM", "ACCESS DENIED", `User ${user.username} denied for ${requiredRight}.`).catch(() => {});
      const fallback = firstAllowedPage(user);
      if (!window.location.pathname.endsWith(`/${fallback}`) && !window.location.pathname.endsWith(fallback)) {
        window.location.href = fallback;
      }
      return null;
    }

    return { user };
  }

  async function addActionLog(page, action, details) {
    try {
      await apiRequest("/api/action-logs", {
        method: "POST",
        body: { page, action, details }
      });
    } catch (err) {
      // Ignore action log failures to avoid blocking UI flow.
    }
  }

  async function getUsers() {
    const data = await apiRequest("/api/users");
    return Array.isArray(data.users) ? data.users : [];
  }

  async function saveManagedUser(userPayload) {
    const payload = {
      username: normalizeUpper(userPayload.username),
      fullName: normalizeUpper(userPayload.fullName),
      password: normalizeUpper(userPayload.password),
      canLogin: Boolean(userPayload.canLogin),
      rights: {
        deviceMaster: Boolean(userPayload.rights && userPayload.rights.deviceMaster),
        userSetup: Boolean(userPayload.rights && userPayload.rights.userSetup),
        actionLog: Boolean(userPayload.rights && userPayload.rights.actionLog),
        userManagement: Boolean(userPayload.rights && userPayload.rights.userManagement)
      }
    };

    try {
      const isUpdate = Boolean(userPayload.id);
      const data = await apiRequest(isUpdate ? `/api/users/${userPayload.id}` : "/api/users", {
        method: isUpdate ? "PUT" : "POST",
        body: payload
      });
      return { ok: true, user: data.user, created: !isUpdate };
    } catch (err) {
      return { ok: false, message: err.message || "FAILED TO SAVE USER." };
    }
  }

  async function deleteManagedUser(id) {
    try {
      await apiRequest(`/api/users/${id}`, { method: "DELETE" });
      return { ok: true };
    } catch (err) {
      return { ok: false, message: err.message || "FAILED TO DELETE USER." };
    }
  }

  return {
    normalizeUpper,
    getCurrentUser,
    hasRight,
    firstAllowedPage,
    apiRequest,
    login,
    logout,
    requireAuth,
    addActionLog,
    getUsers,
    saveManagedUser,
    deleteManagedUser
  };
})();

if (typeof globalThis !== "undefined") {
  globalThis.InventoryAuth = InventoryAuth;
}
