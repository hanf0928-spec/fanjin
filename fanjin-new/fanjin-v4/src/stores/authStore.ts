// authStore：会话/认证核心，从旧 Vue src/stores/user.ts 迁移。
// 登录、注册后必须调 fetchMe() 拉完整会话（含 workspace 列表）。
import { create } from "zustand";
import { bindGuestDraft, clearGuestDraft, readGuestDraft } from "../features/auth/guestDraft";
import { persist } from "zustand/middleware";
import { useSessionStore } from "../features/quick-create/session/sessionStore";
import * as authApi from "../api/auth";
import type { ApiErrorView } from "../api/http";
import type { User } from "../api/types";
import type { AuthSession, Workspace } from "../api/types";
import { clearToken, readAuthToken, saveToken, setUnauthorizedSessionHandler, toApiErrorView } from "../api/http";
import { useProjectStore } from "./projectStore";
import { useWorkspaceStore } from "./workspaceStore";

type AuthState = {
  token: string;
  user: User | null;
  workspaces: Workspace[];
  currentWorkspace: Workspace | null;
  platformPermissions: string[];
  bootstrapped: boolean;
  sessionExpired: boolean;
  loading: boolean;
  error: ApiErrorView | null;

  setToken: (token: string) => void;
  login: (username: string, password: string) => Promise<void>;
  loginWithMfa: (challenge: string, code: string) => Promise<void>;
  /**
   * 仅当后端显式开启自动登录（FANJIN_ENABLE_AUTO_LOGIN=1）时才会生效；
   * 后端未开启则接口 404，这里静默回退，照常走登录页，不影响默认部署。
   */
  autoLogin: () => Promise<void>;
  register: (payload: authApi.RegisterPayload) => Promise<void>;
  fetchMe: () => Promise<void>;
  applySession: (session: AuthSession, preferredWorkspaceId?: string | number | null) => void;
  logout: () => void;
};

type ActiveFetchMe = {
  controller: AbortController;
  generation: number;
  promise: Promise<void>;
  token: string;
};

let authSessionGeneration = 0;
let activeFetchMe: ActiveFetchMe | null = null;

function invalidateActiveFetchMe() {
  authSessionGeneration += 1;
  activeFetchMe?.controller.abort();
  activeFetchMe = null;
}

function isAbortError(error: unknown) {
  return Boolean(error && typeof error === "object" && "name" in error && error.name === "AbortError");
}

function normalizeWorkspace(ws: Workspace, effectivePermissions?: string[]): Workspace {
  return {
    ...ws,
    status: ws.status || "active",
    plan: ws.plan || "team",
    role: ws.memberRole || ws.role || "member",
    ...(effectivePermissions !== undefined
      ? { permissions: Array.from(new Set(effectivePermissions.map(String).map((item) => item.trim()).filter(Boolean))) }
      : {}),
  };
}

function normalizeSession(session: AuthSession, preferredWorkspaceId?: string | number | null) {
  let workspaces = (session.workspaces ?? []).map((workspace) => normalizeWorkspace(workspace));
  const selectedWorkspace = session.workspace
    ?? workspaces.find((workspace) => String(workspace.id) === String(preferredWorkspaceId))
    ?? workspaces[0]
    ?? null;
  const currentWorkspace = selectedWorkspace
    ? normalizeWorkspace(selectedWorkspace, session.permissions)
    : null;
  if (currentWorkspace) {
    const currentIndex = workspaces.findIndex((workspace) => String(workspace.id) === String(currentWorkspace.id));
    if (currentIndex >= 0) {
      workspaces = workspaces.map((workspace, index) => index === currentIndex ? currentWorkspace : workspace);
    } else {
      workspaces = [currentWorkspace, ...workspaces];
    }
  }
  return { currentWorkspace, workspaces };
}

function projectSelectionScope(user: User | null, workspace: Workspace | null) {
  if (!user) return null;
  return JSON.stringify([
    String(user.id),
    workspace ? String(workspace.id) : null,
  ]);
}

function bindAuthoritativeProjectScope(user: User | null, workspace: Workspace | null) {
  const changed = useProjectStore.getState().bindSelectionScope(
    projectSelectionScope(user, workspace),
  );
  if (changed) useSessionStore.getState().clear();
}

function clearScopedCreationState() {
  useProjectStore.getState().resetWorkspaceProjects();
  useSessionStore.getState().clear();
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
      token: "",
      user: null,
      workspaces: [],
      currentWorkspace: null,
      platformPermissions: [],
      bootstrapped: false,
      sessionExpired: false,
      loading: false,
      error: null,

      setToken: (token) => {
        saveToken(token);
        const currentToken = get().token;
        if (token === currentToken) return;
        invalidateActiveFetchMe();
        clearScopedCreationState();
        set({
          token,
          user: null,
          workspaces: [],
          currentWorkspace: null,
          platformPermissions: [],
          bootstrapped: false,
          sessionExpired: false,
          loading: false,
          error: null,
        });
        useWorkspaceStore.getState().reset();
      },

      login: async (username, password) => {
        set({ loading: true, error: null });
        try {
          const result = await authApi.login({ username, password });
          // 登录拿到 token 后，先存下来让后续请求带上 Authorization
          get().setToken(result.token);
          // 拉完整会话（user + workspaces），同时 hydrate workspaceStore
          await get().fetchMe();
        } catch (e) {
          set({ error: toApiErrorView(e) });
          throw e;
        } finally {
          set({ loading: false });
        }
      },

      loginWithMfa: async (challenge, code) => {
        set({ loading: true, error: null });
        try {
          const result = await authApi.loginWithMfa({ challenge, code });
          get().setToken(result.token);
          await get().fetchMe();
        } catch (e) {
          set({ error: toApiErrorView(e) });
          throw e;
        } finally {
          set({ loading: false });
        }
      },

      autoLogin: async () => {
        if (get().token) return;
        set({ loading: true, error: null });
        try {
          const result = await authApi.autoLogin();
          get().setToken(result.token);
          await get().fetchMe();
        } catch (e) {
          // 后端未开启自动登录（404）或暂不可用：保持未登录状态，
          // 交回正常登录页处理，不阻塞应用启动。
          set({ bootstrapped: true, loading: false });
        }
      },

      register: async (payload) => {
        set({ loading: true, error: null });
        try {
          const result = await authApi.register(payload);
          // 邮箱验证路径：不落 session，由页面提示去邮箱点链接。
          if (result?.requiresVerification || !result?.token) {
            return;
          }
          get().setToken(result.token);
          await get().fetchMe();
        } catch (e) {
          set({ error: toApiErrorView(e) });
          throw e;
        } finally {
          set({ loading: false });
        }
      },

      fetchMe: async () => {
        const { token } = get();
        if (!token) {
          set({ bootstrapped: true });
          return;
        }

        if (activeFetchMe?.token === token && !activeFetchMe.controller.signal.aborted) {
          return activeFetchMe.promise;
        }

        invalidateActiveFetchMe();
        const generation = authSessionGeneration;
        const controller = new AbortController();
        const isCurrentRequest = () => (
          generation === authSessionGeneration
          && get().token === token
          && !controller.signal.aborted
        );

        set({ loading: true, error: null });
        const promise = (async () => {
          try {
            const session: AuthSession = await authApi.fetchMe(token, controller.signal);
            if (!isCurrentRequest()) return;

            const { currentWorkspace, workspaces } = normalizeSession(session);
            if (!isCurrentRequest()) return;
            bindAuthoritativeProjectScope(session.user, currentWorkspace);
            if (session.user) bindGuestDraft(session.user.id);
            set({
              user: session.user,
              workspaces,
              currentWorkspace,
              platformPermissions: session.platformAccess?.effectivePermissions ?? [],
              bootstrapped: true,
            });
            // 同步 workspaceStore，避免 workspaceStore 自己再拉一次 /auth/me。
            // applySession 前再次校验，避免 token 切换夹在两个 store 写入之间。
            if (isCurrentRequest()) {
              useWorkspaceStore.getState().applySession(workspaces, currentWorkspace?.id ?? null);
            }
          } catch (e: unknown) {
            if (!isCurrentRequest() || isAbortError(e)) return;
            const status = (e as { status?: number }).status;
            // 只有后端明确判定会话无效时才登出；网络抖动或服务暂时不可用应保留 token。
            if (status === 401) {
              get().logout();
              set({ sessionExpired: true });
            } else if (isCurrentRequest()) {
              // A failed bootstrap is not an authenticated, permission-ready session.
              // Keep the token for recovery, but leave RBAC blocked until a retry succeeds.
              set({ bootstrapped: false, error: toApiErrorView(e) });
            }
          } finally {
            if (isCurrentRequest()) set({ loading: false });
            if (activeFetchMe?.generation === generation) activeFetchMe = null;
          }
        })();

        activeFetchMe = { controller, generation, promise, token };
        return promise;
      },

      applySession: (session, preferredWorkspaceId = null) => {
        // Workspace create/switch responses are newer authoritative sessions.
        // Abort any older /auth/me so it cannot overwrite the selected workspace later.
        invalidateActiveFetchMe();
        const { currentWorkspace, workspaces } = normalizeSession(session, preferredWorkspaceId);
        bindAuthoritativeProjectScope(session.user, currentWorkspace);
        if (session.user) bindGuestDraft(session.user.id);
        set({
          user: session.user,
          workspaces,
          currentWorkspace,
          platformPermissions: session.platformAccess?.effectivePermissions ?? [],
          bootstrapped: true,
          loading: false,
          error: null,
        });
        useWorkspaceStore.getState().applySession(workspaces, currentWorkspace?.id ?? preferredWorkspaceId ?? null);
      },

      logout: () => {
        if (readGuestDraft()?.owner) clearGuestDraft();
        invalidateActiveFetchMe();
        clearToken();
        clearScopedCreationState();
        set({
          token: "",
          user: null,
          workspaces: [],
          currentWorkspace: null,
          platformPermissions: [],
          bootstrapped: false,
          sessionExpired: false,
          loading: false,
          error: null,
        });
        useWorkspaceStore.getState().reset();
      },
    }),
    {
      name: "fanjin-auth",
      // 只持久化 token，其余每次 /auth/me 拉最新
      partialize: (state) => ({ token: state.token }),
      // Older deployments could restore the route session from this Zustand
      // key without restoring the HTTP token key. Reconcile both during
      // hydration, and only accept the persisted token field.
      merge: (persistedState, currentState) => {
        const persistedToken = String((persistedState as Partial<AuthState>)?.token || "").trim();
        const token = readAuthToken() || persistedToken;
        if (token) saveToken(token);
        return { ...currentState, token };
      },
    },
  ),
);

setUnauthorizedSessionHandler((rejectedToken) => {
  const auth = useAuthStore.getState();
  // A delayed response from an old login must not invalidate a newer session.
  if (!auth.token || auth.token.trim() !== rejectedToken) return;
  // fetchMe coalesces concurrent failures and logs out only on an authoritative
  // 401. Endpoint-specific challenges and transient failures keep the token.
  void auth.fetchMe();
});
