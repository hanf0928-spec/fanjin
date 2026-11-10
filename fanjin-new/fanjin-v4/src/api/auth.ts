// Auth API：从旧 Vue 的 src/pages/login、src/pages/auth/register、src/stores/user.ts 迁移。
// 后端约定：POST + JSON，token 原样作为 Authorization 头（无 Bearer 前缀）。
import { apiPost, readApiSettings, ApiError } from "./http";
import type { AuthSession, User } from "./types";

export type LoginPayload = {
  username: string;
  password: string;
};

export type MfaLoginPayload = {
  challenge: string;
  code: string;
};

export type LoginResult = {
  token: string;
  user?: User;
  security?: { mustChangePassword?: boolean };
};

export type TenantTransferExchangeResult = LoginResult & Partial<AuthSession>;

export type RegisterPayload = {
  username: string;
  email: string;
  password: string;
  displayName: string;
  workspaceName: string;
};

/** 注册成功且需要邮箱验证时（生产默认）不会返回 token。 */
export type RegisterResult = {
  token?: string;
  email?: string;
  delivery?: "email" | "development_token";
  requiresVerification?: boolean;
} & Partial<AuthSession>;

export type VerifyEmailPayload = Record<string, never>;

export type AuthHandoffFlow = "password_reset" | "verify_email";

export type ClaimAuthHandoffPayload = {
  locator: string;
  flow: AuthHandoffFlow;
  code?: string;
};

/** 验证成功只确认邮箱所有权；不会自动建立登录会话或返回 token。 */
export type VerifyEmailResult = {
  email: string;
  verified: true;
  alreadyVerified?: boolean;
  autoLogin: false;
};

export type ResendVerificationPayload = {
  email: string;
};

export type ResendVerificationResult = Record<string, unknown>;

/** POST /auth/login → { token, user?, security? }。登录后需再调 fetchMe 拉全量会话。 */
export function login(payload: LoginPayload): Promise<LoginResult> {
  return apiPost<LoginResult, LoginPayload>("/auth/login", payload);
}

/** POST /auth/login/mfa → 使用密码阶段返回的一次性 challenge 完成登录。 */
export function loginWithMfa(payload: MfaLoginPayload): Promise<LoginResult> {
  return apiPost<LoginResult, MfaLoginPayload>("/auth/login/mfa", payload);
}

/**
 * POST /auth/auto-login → 跳过密码校验，直接签发固定管理员会话。
 * 仅当部署方显式开启 FANJIN_ENABLE_AUTO_LOGIN=1 时后端才会响应，
 * 否则返回 404，调用方应静默回退到正常登录流程。
 */
export function autoLogin(): Promise<LoginResult> {
  return apiPost<LoginResult, Record<string, never>>("/auth/auto-login", {});
}


export function exchangeTenantTransfer(code: string): Promise<TenantTransferExchangeResult> {
  return apiPost<TenantTransferExchangeResult, { code: string }>("/auth/tenant-transfer/exchange", { code });
}

export function startTenantTransfer(input: {
  targetOrigin: string;
  targetTenantId?: string | null;
  redirectPath?: string | null;
}): Promise<{ targetTenantId: string; expiresAt: number; redirectUrl: string }> {
  return apiPost("/auth/tenant-transfer/start", input);
}

/** POST /auth/register → 需验证时仅返回 requiresVerification；测试自动验证路径可能仍返回 token。 */
export function register(payload: RegisterPayload): Promise<RegisterResult> {
  return apiPost<RegisterResult, RegisterPayload>("/auth/register", payload);
}

/** POST /auth/verify-email → 使用 HttpOnly browser claim 完成邮箱验证。 */
export function verifyEmail(payload: VerifyEmailPayload): Promise<VerifyEmailResult> {
  return apiPost<VerifyEmailResult, VerifyEmailPayload>("/auth/verify-email", payload);
}

/** Bind a non-authorizing email locator to this browser before completing it. */
export function claimAuthHandoff(payload: ClaimAuthHandoffPayload): Promise<{
  claimed: true;
  flow: AuthHandoffFlow;
}> {
  return apiPost("/auth/handoff/claim", payload);
}

/** POST /auth/resend-verification → 若邮箱已注册且未验证则重发验证信。 */
export function resendVerification(payload: ResendVerificationPayload): Promise<ResendVerificationResult> {
  return apiPost<ResendVerificationResult, ResendVerificationPayload>("/auth/resend-verification", payload);
}

/**
 * GET /auth/me → { user, workspace, workspaces }。
 * 沿用旧 Vue 语义：用原生 fetch，只有 401 才算登出，其它错误（网络/5xx/CORS）保留 token。
 */
export async function fetchMe(token?: string, signal?: AbortSignal): Promise<AuthSession> {
  const settings = readApiSettings();
  const authToken = token || settings.token;
  const response = await fetch(`${settings.baseUrl}/auth/me`, {
    method: "GET",
    signal,
    headers: authToken ? { Authorization: authToken } : {},
  });

  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new ApiError(payload?.message || `会话校验失败：${response.status}`, {
      status: response.status,
      code: payload?.code,
    });
  }
  const data = payload?.data ?? payload;
  return {
    user: data?.user ?? null,
    workspace: data?.workspace ?? null,
    workspaces: data?.workspaces ?? [],
    permissions: Array.isArray(data?.permissions) ? data.permissions.map(String) : undefined,
    platformAccess: {
      role: typeof data?.platformAccess?.role === "string"
        ? data.platformAccess.role
        : null,
      effectivePermissions: Array.isArray(data?.platformAccess?.effectivePermissions)
        ? data.platformAccess.effectivePermissions.map(String)
        : [],
    },
  };
}
