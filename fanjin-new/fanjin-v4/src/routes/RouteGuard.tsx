import { resolvePostLoginRedirect } from "../pages/auth/postLoginRedirect";
// 路由守卫：复刻旧 Vue router/index.ts 的 beforeEach 逻辑
// 检查认证、RBAC 权限、工作区/项目上下文
import { type ReactNode, useEffect, useState } from "react";
import { Navigate, useLocation } from "react-router-dom";
import { Loader2, LogOut, RotateCcw, TriangleAlert } from "lucide-react";
import { useAuthStore } from "../stores/authStore";
import { normalizeProjectId, useProjectStore } from "../stores/projectStore";
import {
  ADMIN_ROLES,
  getConsoleAccess,
  hasAnyRole,
  roleValue,
  type GuardMeta,
} from "./consoleAccess";
import "./RouteGuard.css";

type RouteGuardProps = {
  meta?: GuardMeta;
  children: ReactNode;
};

export const ROUTE_GUARD_SLOW_NOTICE_MS = 8000;

export function isWorkspaceInvitationRoute(pathname: string, search: string) {
  if (pathname !== "/auth/register") return false;
  return Boolean(new URLSearchParams(search).get("invite")?.trim());
}

export function scheduleRouteGuardSlowNotice(
  onSlow: () => void,
  delayMs = ROUTE_GUARD_SLOW_NOTICE_MS,
) {
  const timer = setTimeout(onSlow, delayMs);
  return () => clearTimeout(timer);
}

function ProjectRouteBootstrap({
  children,
  fullPath,
  projectId,
}: {
  children: ReactNode;
  fullPath: string;
  projectId: number;
}) {
  const currentProjectId = useProjectStore((state) => state.currentProjectId);
  const currentProject = useProjectStore((state) => state.currentProject);
  const refreshAndSelectProject = useProjectStore(
    (state) => state.refreshAndSelectProject,
  );
  const [failed, setFailed] = useState(false);
  const ready = (
    normalizeProjectId(currentProjectId) === projectId
    && normalizeProjectId(currentProject?.id) === projectId
  );

  useEffect(() => {
    if (ready) {
      setFailed(false);
      return undefined;
    }

    let active = true;
    setFailed(false);
    void refreshAndSelectProject(projectId, {
      expectedCurrentProjectId: currentProjectId,
      shouldCommit: () => active,
    }).catch(() => {
      if (active) setFailed(true);
    });
    return () => {
      active = false;
    };
  }, [currentProjectId, projectId, ready, refreshAndSelectProject]);

  if (ready) return <>{children}</>;
  if (failed) {
    return (
      <Navigate
        to={`/workbench/project?projectRequired=1&invalidProject=1&redirect=${encodeURIComponent(fullPath)}`}
        replace
      />
    );
  }
  return (
    <div className="routeGuardBootstrap" role="status" aria-live="polite" aria-busy="true">
      <span className="routeGuardBootstrapStatus">
        <Loader2 className="routeGuardBootstrapIcon" aria-hidden="true" size={20} strokeWidth={1.7} />
        <span>正在恢复项目上下文，请稍候…</span>
      </span>
    </div>
  );
}

function permissionDenied(reason: string, blocked: string) {
  return (
    <Navigate
      to={`/workspace/select?permissionDenied=${encodeURIComponent(reason)}&blocked=${encodeURIComponent(blocked)}`}
      replace
    />
  );
}

export function RouteGuard({ meta = {}, children }: RouteGuardProps) {
  const location = useLocation();
  const { token, bootstrapped, sessionExpired, error: bootstrapError } = useAuthStore();
  const fetchMe = useAuthStore((s) => s.fetchMe);
  const autoLogin = useAuthStore((s) => s.autoLogin);
  const logout = useAuthStore((s) => s.logout);
  const currentWorkspace = useAuthStore((s) => s.currentWorkspace);
  const user = useAuthStore((s) => s.user);
  const [bootstrapIsSlow, setBootstrapIsSlow] = useState(false);

  const isPublic = Boolean(meta.public);
  const isGuestOnly = Boolean(meta.guestOnly);
  const requiresAuth = meta.requiresAuth === true || (!isPublic && !isGuestOnly);
  const requiresAdmin = Boolean(meta.requiresAdmin);
  const requiresFinance = Boolean(meta.requiresFinance);
  const requiresFinanceManager = Boolean(meta.requiresFinanceManager);
  const requiresProject = Boolean(meta.requiresProject);
  const requiresWorkspaceManager = Boolean(meta.requiresWorkspaceManager);
  const requiresWorkspaceMembers = Boolean(meta.requiresWorkspaceMembers);
  const requiresBillingAccess = Boolean(meta.requiresBillingAccess);
  const requiresDeveloperAccess = Boolean(meta.requiresDeveloperAccess);
  const fullPath = `${location.pathname}${location.search}`;
  const userRole = roleValue(user?.role);
  const workspaceRole = roleValue(currentWorkspace?.memberRole || currentWorkspace?.role || user?.role || "member");
  const consoleAccess = getConsoleAccess(userRole, workspaceRole, currentWorkspace?.permissions);

  useEffect(() => {
    if (bootstrapped || bootstrapError) {
      setBootstrapIsSlow(false);
      return;
    }
    if (!token && !requiresAuth) {
      // 公开/仅访客页面不需要等待会话恢复，也不触发自动登录。
      setBootstrapIsSlow(false);
      return;
    }

    setBootstrapIsSlow(false);
    const cancelSlowNotice = scheduleRouteGuardSlowNotice(() => setBootstrapIsSlow(true));
    // 已有 token 走正常会话恢复；无 token 且该页面需要登录时，
    // 尝试自动登录（仅部署方显式开启时后端才会响应，否则静默回退登录页）。
    void (token ? fetchMe() : autoLogin());
    return cancelSlowNotice;
  }, [token, bootstrapped, bootstrapError, requiresAuth, fetchMe, autoLogin]);

  // A transient /auth/me failure must never fall through to RBAC with an empty
  // user/workspace. Preserve the token and offer explicit recovery instead.
  if (token && !bootstrapped && bootstrapError) {
    return (
      <main className="routeGuardBootstrap routeGuardBootstrap--error" role="alert" aria-live="assertive">
        <section className="routeGuardRecovery" aria-labelledby="route-guard-recovery-title">
          <span className="routeGuardRecoveryIcon" aria-hidden="true">
            <TriangleAlert size={18} strokeWidth={1.7} />
          </span>
          <div className="routeGuardRecoveryCopy">
            <h1 id="route-guard-recovery-title">暂时无法恢复登录会话</h1>
            <p>{bootstrapError.message || "会话服务暂时不可用，请稍后重试。"}</p>
            <p className="routeGuardRecoveryHint">登录凭据仍已保留，重试成功前不会进行权限判断。</p>
          </div>
          <div className="routeGuardRecoveryActions">
            <button className="routeGuardRecoveryButton routeGuardRecoveryButton--primary" type="button" onClick={() => void fetchMe()}>
              <RotateCcw size={15} strokeWidth={1.7} aria-hidden="true" />
              重试
            </button>
            <button className="routeGuardRecoveryButton" type="button" onClick={logout}>
              <LogOut size={15} strokeWidth={1.7} aria-hidden="true" />
              退出登录
            </button>
          </div>
        </section>
      </main>
    );
  }

  // 慢响应只升级提示，不破坏仍可能有效的登录会话。
  if (token && !bootstrapped) {
    return (
      <div className="routeGuardBootstrap" role="status" aria-live="polite" aria-busy="true">
        <span className="routeGuardBootstrapStatus">
          <Loader2 className="routeGuardBootstrapIcon" aria-hidden="true" size={20} strokeWidth={1.7} />
          <span>{bootstrapIsSlow ? "网络响应较慢，仍在等待…" : "正在恢复登录会话，请稍候…"}</span>
        </span>
      </div>
    );
  }

  // 尚无 token 但该页面需要登录：等待一次自动登录尝试的结果，
  // 避免先闪一下登录页再被自动登录跳转打断。后端未开启自动登录时
  // autoLogin() 会很快把 bootstrapped 置为 true，正常落到登录页。
  if (!token && requiresAuth && !bootstrapped) {
    return (
      <div className="routeGuardBootstrap" role="status" aria-live="polite" aria-busy="true">
        <span className="routeGuardBootstrapStatus">
          <Loader2 className="routeGuardBootstrapIcon" aria-hidden="true" size={20} strokeWidth={1.7} />
          <span>{bootstrapIsSlow ? "网络响应较慢，仍在等待…" : "正在准备登录会话，请稍候…"}</span>
        </span>
      </div>
    );
  }

  // 工作区邀请同时服务于新用户和已有账号。已有账号必须保留当前会话，
  // 进入邀请页后再由页面校验登录邮箱是否与受邀邮箱一致。
  const allowsAuthenticatedInvitation = isWorkspaceInvitationRoute(location.pathname, location.search);

  // 已登录用户访问其他 guestOnly 页面（登录/普通注册），跳转到默认页
  if (token && isGuestOnly && !allowsAuthenticatedInvitation) {
    const destination = location.pathname === "/auth/login"
      ? resolvePostLoginRedirect(new URLSearchParams(location.search).get("redirect"))
      : "/workbench/create";
    return <Navigate to={currentWorkspace ? destination : `/workspace/select?redirect=${encodeURIComponent(destination)}`} replace />;
  }

  // 需要认证但未登录
  if (requiresAuth && !token) {
    return <Navigate to={`/auth/login?redirect=${encodeURIComponent(fullPath)}${sessionExpired ? "&reason=session-expired" : ""}`} replace />;
  }

  // 需要 admin 权限
  if (requiresAdmin) {
    const isAdmin = hasAnyRole(userRole, ADMIN_ROLES);
    if (!isAdmin) {
      return permissionDenied("admin", fullPath);
    }
  }

  // 需要 finance 权限
  if (requiresFinance && !consoleAccess.finance) {
    return permissionDenied("finance", fullPath);
  }

  if (requiresFinanceManager && !consoleAccess.financeManager) {
    return permissionDenied("finance-manager", fullPath);
  }

  // 需要工作区上下文（workbench/developer/settings 路径）
  const needsWorkspace =
    requiresAuth &&
    !requiresAdmin &&
    !requiresFinance &&
    !requiresFinanceManager &&
    (location.pathname.startsWith("/workbench") ||
      location.pathname.startsWith("/developer") ||
      location.pathname.startsWith("/settings") ||
      location.pathname.startsWith("/workspace"));

  const isWorkspaceSelection = location.pathname === "/workspace/select";
  if (needsWorkspace && !isWorkspaceSelection && !currentWorkspace) {
    return <Navigate to={`/workspace/select?redirect=${encodeURIComponent(fullPath)}`} replace />;
  }

  if (requiresWorkspaceManager && !consoleAccess.workspaceManager) {
    return permissionDenied("workspace-manage", fullPath);
  }

  if (requiresWorkspaceMembers && !consoleAccess.workspaceMembers) {
    return permissionDenied("workspace-members", fullPath);
  }

  if (requiresBillingAccess && !consoleAccess.billing) {
    return permissionDenied("billing", fullPath);
  }

  if (requiresDeveloperAccess && !consoleAccess.developer) {
    return permissionDenied("developer", fullPath);
  }

  // 需要项目上下文
  if (requiresProject) {
    const routeProjectId = normalizeProjectId(
      new URLSearchParams(location.search).get("projectId"),
    );
    const storedProjectId = normalizeProjectId(
      useProjectStore.getState().currentProjectId,
    );
    const targetProjectId = routeProjectId ?? storedProjectId;
    if (!targetProjectId) {
      return <Navigate to={`/workbench/project?projectRequired=1&redirect=${encodeURIComponent(fullPath)}`} replace />;
    }
    return (
      <ProjectRouteBootstrap
        fullPath={fullPath}
        projectId={targetProjectId}
      >
        {children}
      </ProjectRouteBootstrap>
    );
  }

  return <>{children}</>;
}
