const InventoryAuth = (() => {
  const USERS_KEY = "inventoryUsers";
  const SESSION_KEY = "inventorySession";
  const ACTION_LOG_STORAGE_KEY = "inventoryActionLogs";
  const MAX_ACTION_LOGS = 2000;
  const RIGHTS = ["deviceMaster", "userSetup", "actionLog", "userManagement"];

  function generateId() {
    return typeof crypto !== "undefined" && typeof crypto.randomUUID === "function"
      ? crypto.randomUUID()
      : `id-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  }

  function normalizeUpper(value) {
    return String(value || "").trim().toUpperCase();
  }

  function safeParse(raw, fallback) {
    try {
      const value = JSON.parse(raw);
      return value == null ? fallback : value;
    } catch (err) {
      return fallback;
    }
  }

  function getUsers() {
    return safeParse(localStorage.getItem(USERS_KEY), []);
  }

  function saveUsers(users) {
    localStorage.setItem(USERS_KEY, JSON.stringify(users));
  }

  function addActionLog(page, action, details) {
    try {
      const logs = safeParse(localStorage.getItem(ACTION_LOG_STORAGE_KEY), []);
      logs.unshift({
        id: generateId(),
        timestamp: new Date().toISOString(),
        page,
        action,
        details
      });
      localStorage.setItem(ACTION_LOG_STORAGE_KEY, JSON.stringify(logs.slice(0, MAX_ACTION_LOGS)));
    } catch (err) {
      // Ignore logging failures to avoid blocking core flows like login/logout.
    }
  }

  function ensureBootstrapAdmin() {
    const users = getUsers();
    const hasRecoverableUser = users.some((user) => {
      const rights = user && user.rights ? user.rights : {};
      return Boolean(
        user &&
        user.canLogin &&
        (rights.deviceMaster || rights.userSetup || rights.actionLog || rights.userManagement)
      );
    });

    if (users.length > 0 && hasRecoverableUser) return;

    const now = new Date().toISOString();
    const adminIndex = users.findIndex((user) => normalizeUpper(user.username) === "ADMIN");
    const adminUser = {
      id: adminIndex >= 0 && users[adminIndex] && users[adminIndex].id ? users[adminIndex].id : generateId(),
      username: "ADMIN",
      fullName: "SYSTEM ADMINISTRATOR",
      password: "ADMIN123",
      canLogin: true,
      rights: {
        deviceMaster: true,
        userSetup: true,
        actionLog: true,
        userManagement: true
      },
      createdAt: adminIndex >= 0 && users[adminIndex] && users[adminIndex].createdAt ? users[adminIndex].createdAt : now,
      updatedAt: now
    };

    let nextUsers = users;
    if (adminIndex >= 0) {
      nextUsers = users.map((entry, index) => (index === adminIndex ? adminUser : entry));
      saveUsers(nextUsers);
      addActionLog("SYSTEM", "RECOVERY", "Recovered ADMIN account (ADMIN / ADMIN123).");
      return;
    }

    nextUsers = [...users, adminUser];
    saveUsers(nextUsers);
    addActionLog("SYSTEM", "BOOTSTRAP", "Created default ADMIN user.");
  }

  function getSession() {
    return safeParse(localStorage.getItem(SESSION_KEY), null);
  }

  function setSession(session) {
    localStorage.setItem(SESSION_KEY, JSON.stringify(session));
  }

  function clearSession() {
    localStorage.removeItem(SESSION_KEY);
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

  function getCurrentUser() {
    ensureBootstrapAdmin();
    const session = getSession();
    if (!session || !session.username) return null;
    const username = normalizeUpper(session.username);
    const users = getUsers();
    const user = users.find((entry) => normalizeUpper(entry.username) === username);
    if (!user || !user.canLogin) return null;
    return user;
  }

  function login(username, password) {
    ensureBootstrapAdmin();
    const normalizedUsername = normalizeUpper(username);
    const normalizedPassword = normalizeUpper(password);
    if (!normalizedUsername || !normalizedPassword) {
      addActionLog("SYSTEM", "LOGIN FAILED", "Missing username or password.");
      return { ok: false, message: "USERNAME AND PASSWORD ARE REQUIRED." };
    }

    const users = getUsers();
    const user = users.find((entry) => normalizeUpper(entry.username) === normalizedUsername);
    if (!user) {
      addActionLog("SYSTEM", "LOGIN FAILED", `Unknown user ${normalizedUsername}.`);
      return { ok: false, message: "INVALID USERNAME OR PASSWORD." };
    }
    if (!user.canLogin) {
      addActionLog("SYSTEM", "LOGIN FAILED", `Disabled user ${normalizedUsername}.`);
      return { ok: false, message: "THIS USER IS DISABLED." };
    }
    if (normalizeUpper(user.password) !== normalizedPassword) {
      addActionLog("SYSTEM", "LOGIN FAILED", `Incorrect password for ${normalizedUsername}.`);
      return { ok: false, message: "INVALID USERNAME OR PASSWORD." };
    }

    setSession({
      username: user.username,
      loginAt: new Date().toISOString()
    });
    addActionLog("SYSTEM", "LOGIN", `User ${user.username} logged in.`);
    return { ok: true, user, redirect: firstAllowedPage(user) };
  }

  function logout() {
    const user = getCurrentUser();
    clearSession();
    if (user) {
      addActionLog("SYSTEM", "LOGOUT", `User ${user.username} logged out.`);
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
      addActionLog("SYSTEM", "ACCESS DENIED", `User ${user.username} denied for ${requiredRight}.`);
      const fallback = firstAllowedPage(user);
      if (!window.location.pathname.endsWith(`/${fallback}`) && !window.location.pathname.endsWith(fallback)) {
        window.location.href = fallback;
      }
      return null;
    }

    return { user };
  }

  function sanitizeRights(rights) {
    const clean = {};
    RIGHTS.forEach((key) => {
      clean[key] = Boolean(rights && rights[key]);
    });
    return clean;
  }

  function saveManagedUser(userPayload) {
    ensureBootstrapAdmin();
    const users = getUsers();
    const now = new Date().toISOString();
    const normalizedUsername = normalizeUpper(userPayload.username);
    const normalizedFullName = normalizeUpper(userPayload.fullName);
    const normalizedPassword = normalizeUpper(userPayload.password);

    if (!normalizedUsername) {
      return { ok: false, message: "USERNAME IS REQUIRED." };
    }
    if (!normalizedFullName) {
      return { ok: false, message: "FULL NAME IS REQUIRED." };
    }
    if (!normalizedPassword) {
      return { ok: false, message: "PASSWORD IS REQUIRED." };
    }

    const existing = users.find((entry) => entry.id === userPayload.id);
    const duplicate = users.find((entry) =>
      normalizeUpper(entry.username) === normalizedUsername && entry.id !== userPayload.id
    );
    if (duplicate) {
      return { ok: false, message: "USERNAME ALREADY EXISTS." };
    }

    const nextUser = {
      id: existing ? existing.id : generateId(),
      username: normalizedUsername,
      fullName: normalizedFullName,
      password: normalizedPassword,
      canLogin: Boolean(userPayload.canLogin),
      rights: sanitizeRights(userPayload.rights),
      createdAt: existing ? existing.createdAt : now,
      updatedAt: now
    };

    if (!Object.values(nextUser.rights).some(Boolean)) {
      return { ok: false, message: "AT LEAST ONE RIGHT MUST BE ENABLED." };
    }

    const nextUsers = existing
      ? users.map((entry) => (entry.id === existing.id ? nextUser : entry))
      : [...users, nextUser];

    const activeManagers = nextUsers.filter((entry) => entry.canLogin && hasRight(entry, "userManagement"));
    if (activeManagers.length === 0) {
      return { ok: false, message: "AT LEAST ONE ACTIVE USER MANAGER IS REQUIRED." };
    }

    saveUsers(nextUsers);
    const actor = getCurrentUser();
    addActionLog(
      "User Management Page",
      existing ? "UPDATE USER" : "CREATE USER",
      `${actor ? actor.username : "SYSTEM"} -> ${nextUser.username} (${nextUser.canLogin ? "ENABLED" : "DISABLED"})`
    );
    return { ok: true, user: nextUser, created: !existing };
  }

  function deleteManagedUser(id) {
    ensureBootstrapAdmin();
    const users = getUsers();
    const target = users.find((entry) => entry.id === id);
    if (!target) return { ok: false, message: "USER NOT FOUND." };

    const admins = users.filter((entry) => hasRight(entry, "userManagement") && entry.canLogin);
    if (admins.length === 1 && admins[0].id === id) {
      return { ok: false, message: "CANNOT DELETE THE LAST ACTIVE USER MANAGER." };
    }

    const currentUser = getCurrentUser();
    if (currentUser && currentUser.id === id) {
      return { ok: false, message: "YOU CANNOT DELETE YOUR OWN ACCOUNT." };
    }

    const nextUsers = users.filter((entry) => entry.id !== id);
    saveUsers(nextUsers);
    addActionLog("User Management Page", "DELETE USER", `${currentUser ? currentUser.username : "SYSTEM"} -> ${target.username}`);
    return { ok: true };
  }

  return {
    RIGHTS,
    USERS_KEY,
    SESSION_KEY,
    ACTION_LOG_STORAGE_KEY,
    normalizeUpper,
    ensureBootstrapAdmin,
    getUsers,
    getCurrentUser,
    hasRight,
    firstAllowedPage,
    login,
    logout,
    requireAuth,
    addActionLog,
    saveManagedUser,
    deleteManagedUser
  };
})();

if (typeof globalThis !== "undefined") {
  globalThis.InventoryAuth = InventoryAuth;
}
