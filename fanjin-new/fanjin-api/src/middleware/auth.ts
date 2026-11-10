import { NextFunction, Request, Response } from "express";
import u from "@/utils";
import { AuthError, resolveSessionFromAuthorization } from "@/lib/auth";
import {
  authenticatePortraitManualReviewPreviewGrant,
  clearPortraitManualReviewPreviewGrant,
  isPortraitManualReviewPreviewGrantRequest,
  PortraitManualReviewPreviewGrantError,
  setPortraitManualReviewPreviewPrivateHeaders,
} from "@/lib/portraitManualReviewPreviewGrant";
import { ApiKeyAuthenticationError, preAuthenticateApiKey } from "@/middleware/apiKeyAuth";
import { isRecoveryOnlyMode } from "@/lib/recoveryOnlyMode";

import { authenticateAdminMachineRequest, AdminMachineCredentialError } from "@/lib/adminMachineCredentials";

const PUBLIC_API_PATHS = new Set([
  "/api/auth/login",
  "/api/auth/login/mfa",
  "/api/auth/auto-login",
  "/api/auth/register",
  "/api/auth/invitations/preview",
  "/api/auth/invitations/accept",
  "/api/auth/forgot-password",
  "/api/auth/handoff/claim",
  "/api/auth/registration-policy",
  "/api/auth/reset-password",
  "/api/auth/verify-email",
  "/api/auth/resend-verification",
  "/api/auth/oauth/providers",
  "/api/auth/oauth/exchange",
  "/api/login/login",
  "/api/public/pricing",
  "/api/runtime/tenant",
  "/api/auth/tenant-transfer/exchange",
]);
const PLATFORM_ADMIN_ROLES = new Set(["root", "admin", "super_admin"]);
const PLATFORM_FINANCE_ROLES = new Set(["finance_viewer", "finance_operator", "finance_manager"]);

function normalizePath(path: string): string {
  return path.length > 1 ? path.replace(/\/+$/, "") : path;
}

function isRelayApiPath(path: string): boolean {
  return (
    path === "/api/mcp" || path.startsWith("/api/mcp/") ||
    path === "/api/tools/v1" || path.startsWith("/api/tools/v1/") ||
    path === "/v1" ||
    path.startsWith("/v1/") ||
    path === "/v1beta" ||
    path.startsWith("/v1beta/") ||
    path.startsWith("/api/v3/contents/generations/") ||
    path === "/api/v3/portrait-assets" ||
    path.startsWith("/api/mj/") ||
    path.startsWith("/api/suno/")
  );
}

function isAuthenticatedApiPath(path: string): boolean {
  return (
    path === "/api" ||
    path.startsWith("/api/") ||
    path === "/v1" ||
    path.startsWith("/v1/") ||
    path === "/v1beta" ||
    path.startsWith("/v1beta/")
  );
}

function isPrivilegedSettingsPath(path: string): boolean {
  return (
    path.startsWith("/api/agent/config/") ||
    path.startsWith("/api/setting/vendorConfig/") ||
    path === "/api/setting/agentDeploy/agentSetKey" ||
    path === "/api/setting/agentDeploy/deployAgentModel" ||
    path === "/api/setting/agentDeploy/updateAgentModel" ||
    path === "/api/setting/agentDeploy/updateUseMode" ||
    path === "/api/setting/about/downloadApp" ||
    path === "/api/setting/modelMap/bindingPrompt" ||
    path === "/api/setting/modelMap/deletePrompt" ||
    path === "/api/setting/modelMap/savePrompt" ||
    path === "/api/setting/modelMap/updatePrompt" ||
    path === "/api/setting/dev/updateSwitchAiDevTool" ||
    path === "/api/setting/fileManagement/openFolder" ||
    path === "/api/setting/memoryConfig/delAllMemory" ||
    path === "/api/setting/memoryConfig/sureMemory" ||
    path === "/api/setting/promptManage/getPrompt" ||
    path === "/api/setting/promptManage/updatePrompt" ||
    path === "/api/setting/skillManagement/saveSkillContent" ||
    path === "/api/setting/dbConfig/clearData" ||
    path === "/api/setting/dbConfig/clearTable" ||
    path === "/api/other/deleteAllData"
  );
}

function canPassAdminPathGuard(path: string, role: string): boolean {
  return PLATFORM_ADMIN_ROLES.has(role) || PLATFORM_FINANCE_ROLES.has(role);
}

function isPublicOAuthPath(path: string): boolean {
  const normalized = normalizePath(path);
  if (normalized === "/api/auth/oauth/providers") return true;
  // /api/auth/oauth/:provider/authorize|callback
  return /^\/api\/auth\/oauth\/[a-z]+\/(authorize|callback)$/.test(normalized);
}

function isPublicPaymentCallbackPath(path: string): boolean {
  return /^\/api\/billing\/payment\/callbacks\/(wechat_v3|alipay)\/[A-Z][A-Z0-9_-]{1,63}\/[a-zA-Z0-9_-]{1,64}$/.test(normalizePath(path));
}

function isPublicPortraitCallbackPath(path: string): boolean {
  return normalizePath(path) === "/api/public/portrait-assets/callback";
}

function isPublicCanvasPublicationPath(path: string): boolean {
  const normalized = normalizePath(path);
  return /^\/api\/public\/canvas\/(shares\/[A-Za-z0-9_-]{32}|fjtv(?:\/[A-Za-z0-9_-]{32})?)$/.test(normalized);
}

function isPublicReleaseControlJwksPath(path: string): boolean {
  return normalizePath(path) === "/api/releaseControl/well-known/jwks.json";
}

/**
 * Candidate proof requests must authenticate against the exact session row
 * without changing it. The runtime authority binds the complete business
 * projection (including o_user_session), so an ordinary lastSeenAt touch would
 * invalidate the authority before the proof handler can answer. Keep this list
 * narrow: excluding the session table from the projection or bypassing auth
 * would hide real token/workspace/revocation drift.
 */
function isReadOnlyCandidateProofPath(path: string): boolean {
  const normalized = normalizePath(path);
  return normalized === "/api/internal/candidate-runtime-attestation"
    || normalized === "/api/internal/candidate-runtime-database-attestation"
    || normalized === "/api/internal/candidate-exact-authorization"
    || normalized.startsWith("/api/internal/candidate-exact-authorization/");
}

function isReferenceAssetFilePath(path: string): boolean {
  return normalizePath(path) === "/api/assets/getReferenceFile";
}

function hideReferenceAssetFile(res: Response) {
  res.setHeader("Cache-Control", "private, no-store, max-age=0");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("X-Content-Type-Options", "nosniff");
  return res.status(404).send({ message: "资源不存在" });
}

function allowsMissingWorkspaceContext(path: string): boolean {
  const normalized = normalizePath(path);
  return normalized === "/api/auth/logout"
    || normalized === "/api/auth/me"
    || normalized === "/api/auth/oauth/bind"
    || normalized.startsWith("/api/account/")
    || normalized === "/api/workspace/create"
    || normalized === "/api/workspace/switch";
}

export default async function authMiddleware(req: Request, res: Response, next: NextFunction) {
  if (req.method === "OPTIONS") return next();
  if (!isAuthenticatedApiPath(req.path)) return next();
  try {
    if (await authenticateAdminMachineRequest(req)) return next();
  } catch (caught) {
    if (caught instanceof AdminMachineCredentialError) return res.status(caught.status).send({ message: "管理机器凭据不可用", code: caught.code });
    return res.status(503).send({ message: "管理机器凭据认证暂不可用", code: "ADMIN_MACHINE_AUTH_UNAVAILABLE" });
  }
  if (
    PUBLIC_API_PATHS.has(normalizePath(req.path))
    || isPublicOAuthPath(req.path)
    || isPublicPaymentCallbackPath(req.path)
    || isPublicPortraitCallbackPath(req.path)
    || isPublicCanvasPublicationPath(req.path)
    || isPublicReleaseControlJwksPath(req.path)
  ) return next();
  if (isRelayApiPath(req.path)) {
    try {
      const apiKey = await preAuthenticateApiKey(req);
      if (apiKey) return next();
    } catch (err: any) {
      if (err instanceof ApiKeyAuthenticationError) {
        return res.status(err.status).send({ message: err.message, code: err.code });
      }
      console.error("[auth] API Key identity validation failed", err?.message || err);
      return res.status(503).send({ message: "API Key 认证服务暂不可用", code: "api_key_auth_unavailable" });
    }
  }

  // Native <video> requests cannot attach the SPA's Authorization header.
  // Only this exact GET may authenticate with the short-lived HttpOnly grant;
  // any supplied Authorization value continues through the canonical session
  // verifier and is never downgraded to cookie auth after a bearer failure.
  if (
    isPortraitManualReviewPreviewGrantRequest(req.method, req.path)
    && !String(req.headers.authorization || "").trim()
  ) {
    setPortraitManualReviewPreviewPrivateHeaders(res);
    try {
      const resolved = await authenticatePortraitManualReviewPreviewGrant(
        u.db as any,
        req,
      );
      (req as any).auth = resolved.auth;
      (req as any).user = resolved.user;
      return next();
    } catch (err) {
      clearPortraitManualReviewPreviewGrant(res);
      if (err instanceof PortraitManualReviewPreviewGrantError) {
        return res.status(err.status).send({ message: err.message, code: err.code });
      }
      console.error("[auth] portrait preview grant validation failed");
      return res.status(503).send({
        message: "视频预览认证服务暂不可用",
        code: "PORTRAIT_REVIEW_PREVIEW_AUTH_UNAVAILABLE",
      });
    }
  }

  try {
    const recoveryOnly = isRecoveryOnlyMode();
    const readOnlyCandidateProof = isReadOnlyCandidateProofPath(req.path);
    const resolved = await resolveSessionFromAuthorization(
      u.db as any,
      req.headers.authorization || "",
      {
        // Cross-account OAuth merge is deliberately an offline-only
        // operation. Its online fail-close endpoint must leave the complete
        // account/session/token surface byte-for-byte unchanged.
        touchSession: !recoveryOnly
          && !readOnlyCandidateProof
          && normalizePath(req.path) !== "/api/auth/oauth/bind",
        revokeExpiredSession: !recoveryOnly && !readOnlyCandidateProof,
      },
    );
    if (!resolved) {
      if (isReferenceAssetFilePath(req.path)) return hideReferenceAssetFile(res);
      return res.status(401).send({ message: "未提供token" });
    }
    const rawToken = String(resolved.rawToken || "");
    const decoded = resolved.payload as any;
    const session = resolved.session as any;
    const user = resolved.user as any;
    const workspaceId = resolved.workspaceId ? String(resolved.workspaceId) : null;
    const authUser = {
      ...decoded,
      id: Number(user.id),
      name: user.name,
      role: user.role ?? decoded.role,
      status: user.status,
      authorizationRevision: Number(user.authorizationRevision || 0),
      workspaceId,
    };
    (req as any).auth = {
      user: authUser,
      session,
      workspaceId,
      token: rawToken,
    };
    (req as any).user = authUser;

    const authRole = String(authUser.role || "").toLowerCase();
    if (
      !workspaceId
      && !PLATFORM_ADMIN_ROLES.has(authRole)
      && !(
        PLATFORM_FINANCE_ROLES.has(authRole)
        && (
          req.path.startsWith("/api/admin/finance")
          || req.path.startsWith("/api/admin/billing/serviceRequests/")
        )
      )
      && !allowsMissingWorkspaceContext(req.path)
    ) {
      return res.status(403).send({
        message: "当前会话没有可用的工作区上下文",
        code: "WORKSPACE_CONTEXT_REQUIRED",
      });
    }

    if ((req.path.startsWith("/api/admin/") || isPrivilegedSettingsPath(normalizePath(req.path))) && !canPassAdminPathGuard(req.path, authRole)) {
      return res.status(403).send({ message: "需要平台管理员权限" });
    }

    next();
  } catch (err: any) {
    if (err instanceof AuthError) {
      if (isReferenceAssetFilePath(req.path)) return hideReferenceAssetFile(res);
      return res.status(err.status).send({ message: err.message, code: err.code });
    }
    if (/JsonWebTokenError|TokenExpiredError|NotBeforeError/.test(String(err?.name || ""))) {
      if (isReferenceAssetFilePath(req.path)) return hideReferenceAssetFile(res);
      return res.status(401).send({ message: "无效的token" });
    }
    console.error("[auth] session validation failed", err?.message || err);
    return res.status(503).send({ message: "认证服务暂不可用" });
  }
}
