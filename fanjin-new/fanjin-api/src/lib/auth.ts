import crypto from "crypto";
import jwt from "jsonwebtoken";
import { Knex } from "knex";
import { v4 as uuid } from "uuid";
import {
  getEffectiveWorkspacePermissions,
  getRolePermissions,
  parseWorkspaceMemberPermissions,
} from "@/middleware/permissions";
import {
  financeRoles,
  identityContractVersion,
  platformRoles,
  userStatuses,
  workspaceMemberStatuses,
  workspaceRoles,
  workspaceStatuses,
  type FinanceRole,
  type IdentitySubjectV1,
  type LegacyUserRole,
  type PlatformRole,
  type UserStatus,
  type WorkspaceMemberStatus,
  type WorkspaceRole,
  type WorkspaceStatus,
} from "@/lib/sharedTypes";
import { getConsistentWorkspaceRole } from "@/lib/workspaceOwnership";
import { ensureWorkspaceBillingAccountRecord } from "@/lib/workspaceBillingAccount";
import { insertAndReturnId } from "@/lib/dbDialect";
import {
  checkLoginLimit,
  clearLoginFailures,
  DEFAULT_PASSWORD_POLICY,
  effectiveLoginLimit,
  effectiveIpLoginLimit,
  getAccountSecurityPolicy,
  isLoginIpAllowed,
  loginIdentityHash,
  loginIpIdentityHash,
  recordLoginFailure,
  type PasswordPolicy,
  validatePasswordAgainstPolicy,
} from "@/lib/accountSecurity";
import {
  issueMfaLoginChallenge,
  MfaError,
  readMfaLoginChallenge,
  verifyMfaCredential,
} from "@/lib/mfa";
import { resolvePasswordResetPublicBaseUrl } from "@/lib/passwordResetConfig";
import { isMailConfigured, sendMail } from "@/lib/mailer/smtpMailer";
import { buildPasswordResetMessage, resolveMailLogoUrl } from "@/lib/mailer/templates";
import {
  authHandoffSeedHash,
  consumeAuthHandoffClaim,
  createAuthHandoffIssue,
} from "@/lib/authHandoff";
import {
  deleteUnverifiedRegistration,
  issueEmailVerification,
  sendEmailVerificationMail,
} from "@/lib/emailVerification";
import { AuthError } from "@/lib/authErrors";
import { hashPassword, isPasswordHash, verifyPassword } from "@/lib/passwordHash";
import { isRecoveryOnlyMode } from "@/lib/recoveryOnlyMode";
import { ensureUserAttributionInTransaction } from "@/lib/tenantAttribution";

export { hashPassword, isPasswordHash, verifyPassword } from "@/lib/passwordHash";
export { migrateRootAccount } from "@/lib/rootAccountMigration";

const PASSWORD_RESET_TTL_MS = 30 * 60 * 1000;
const PASSWORD_RESET_TOKEN_TYPE = "password_reset";
const PASSWORD_RESET_CLAIM_TYPE = "password_reset_browser_claim";
const DEFAULT_WORKSPACE_ID = "default";
const DEFAULT_WORKSPACE_NAME = "Default Workspace";

async function deliverPasswordResetEmail(input: {
  email: string;
  username: string;
  resetUrl: string;
  code: string;
}): Promise<void> {
  const publicBaseUrl = resolvePasswordResetPublicBaseUrl();
  if (!publicBaseUrl) throw new Error("PUBLIC_BASE_URL_MISSING");
  const message = buildPasswordResetMessage({
    to: input.email,
    resetUrl: input.resetUrl,
    resetCode: input.code,
    username: input.username,
    logoUrl: resolveMailLogoUrl(publicBaseUrl),
    brandName: "繁境 Fanjin",
  });
  await sendMail({
    to: input.email,
    subject: message.subject,
    text: message.text,
    html: message.html,
  });
}

export { AuthError };

export interface RequestAuthInfo {
  userAgent?: string;
  ip?: string;
  handoffSeed?: string | null;
  /** Server-verified factor used to create this session. */
  stepUpMethod?: "password" | "totp" | "recovery";
}

export interface AuthTokenPayload {
  id: number;
  name: string;
  role?: string | null;
  workspaceId?: string | null;
  sid?: string;
}

interface PasswordResetRateLimit {
  maxRetries: number;
  lockMinutes: number;
}

function boundedPasswordResetInteger(raw: unknown, fallback: number, minimum: number, maximum: number): number {
  const value = Number(raw);
  if (!Number.isFinite(value)) return fallback;
  return Math.min(maximum, Math.max(minimum, Math.trunc(value)));
}

function passwordResetRateLimitHash(kind: "account" | "ip", value: string): string {
  const normalized = String(value || "").trim().toLowerCase() || "unknown";
  return crypto.createHash("sha256").update(`password-reset:${kind}:${normalized}`).digest("hex");
}

function passwordResetRateLimits(): { account: PasswordResetRateLimit; ip: PasswordResetRateLimit } {
  const lockMinutes = boundedPasswordResetInteger(
    process.env.FANJIN_PASSWORD_RESET_LOCK_MINUTES,
    60,
    1,
    1440,
  );
  // recordLoginFailure blocks the request that reaches maxRetries. Adding one
  // lets exactly the configured number of reset requests through per hour.
  return {
    account: {
      maxRetries: boundedPasswordResetInteger(
        process.env.FANJIN_PASSWORD_RESET_ACCOUNT_MAX_PER_HOUR,
        5,
        1,
        1000,
      ) + 1,
      lockMinutes,
    },
    ip: {
      maxRetries: boundedPasswordResetInteger(
        process.env.FANJIN_PASSWORD_RESET_IP_MAX_PER_HOUR,
        30,
        1,
        10000,
      ) + 1,
      lockMinutes,
    },
  };
}

export async function enforcePasswordResetRequestRateLimit(
  knex: Knex,
  input: { identifier: string; userId?: number | null; ip?: string; timestamp?: number },
): Promise<void> {
  const timestamp = input.timestamp ?? now();
  const limits = passwordResetRateLimits();
  // Key the account bucket by the submitted identifier for both existing and
  // unknown users. Using a resolved user id here would let callers compare two
  // aliases and infer whether they belong to the same account from 429 timing.
  const accountPrincipal = `identifier:${String(input.identifier || "").trim().toLowerCase()}`;
  const normalizedIp = String(input.ip || "").trim().replace(/^::ffff:/i, "") || "unknown";
  const accountIdentity = passwordResetRateLimitHash("account", accountPrincipal);
  const ipIdentity = passwordResetRateLimitHash("ip", normalizedIp);

  const [accountCurrent, ipCurrent] = await Promise.all([
    checkLoginLimit(knex, accountIdentity, limits.account, timestamp),
    checkLoginLimit(knex, ipIdentity, limits.ip, timestamp),
  ]);
  const currentBlock = accountCurrent.blocked ? accountCurrent : ipCurrent;
  if (currentBlock.blocked) {
    throw new AuthError("密码重置请求过于频繁，请稍后重试", 429, {
      code: "PASSWORD_RESET_RATE_LIMITED",
      retryAfterSeconds: currentBlock.retryAfterSeconds,
    });
  }

  const [accountRecorded, ipRecorded] = await Promise.all([
    recordLoginFailure(knex, {
      identityHash: accountIdentity,
      userId: input.userId ?? null,
      limit: limits.account,
      timestamp,
    }),
    recordLoginFailure(knex, {
      identityHash: ipIdentity,
      userId: null,
      limit: limits.ip,
      timestamp,
    }),
  ]);
  const recordedBlock = accountRecorded.blocked ? accountRecorded : ipRecorded;
  if (recordedBlock.blocked) {
    throw new AuthError("密码重置请求过于频繁，请稍后重试", 429, {
      code: "PASSWORD_RESET_RATE_LIMITED",
      retryAfterSeconds: recordedBlock.retryAfterSeconds,
    });
  }
}

function now(): number {
  return Date.now();
}

function nextMonotonicTimestamp(
  values: unknown[],
  timestamp = now(),
): number {
  let next = timestamp;
  for (const value of values) {
    const previous = Number(value || 0);
    if (Number.isFinite(previous)) next = Math.max(next, previous + 1);
  }
  return next;
}

async function lockPasswordResetTokenFamily(
  trx: Knex.Transaction,
  userId: number,
): Promise<any[]> {
  return await trx<any>("o_auth_token")
    .where({ userId })
    .whereIn("type", [PASSWORD_RESET_TOKEN_TYPE, PASSWORD_RESET_CLAIM_TYPE])
    .orderBy("createdAt", "asc")
    .orderBy("id", "asc")
    .forUpdate()
    .select("*");
}

async function markUnusedPasswordResetFamilyUsed(
  trx: Knex.Transaction,
  userId: number,
  timestamp: number,
): Promise<void> {
  await trx<any>("o_auth_token")
    .where({ userId })
    .whereIn("type", [PASSWORD_RESET_TOKEN_TYPE, PASSWORD_RESET_CLAIM_TYPE])
    .whereNull("usedAt")
    .update({ usedAt: timestamp });
}

export async function updatePasswordWithHistory(
  client: Knex | Knex.Transaction,
  input: {
    userId: number;
    password: string;
    policy?: PasswordPolicy;
    timestamp?: number;
  },
): Promise<void> {
  if (!(client as any).isTransaction) {
    await (client as Knex).transaction(async (trx) => updatePasswordWithHistory(trx, input));
    return;
  }

  const policy = input.policy || DEFAULT_PASSWORD_POLICY;
  const passwordError = validatePasswordAgainstPolicy(input.password, policy);
  if (passwordError) throw new AuthError(passwordError);
  const user = await (client as any)("o_user")
    .where({ id: input.userId })
    .select("password", "passwordChangedAt", "updatedAt")
    .forUpdate()
    .first();
  if (!user) throw new AuthError("用户不存在", 404);

  if (await verifyPassword(input.password, user.password)) {
    throw new AuthError("新密码不能与当前密码相同", 409, { code: "PASSWORD_REUSED" });
  }
  const historyCount = Math.max(0, Number(policy.rejectHistoryCount || 0));
  if (historyCount > 0) {
    const history = await (client as any)("o_user_password_history")
      .where({ userId: input.userId })
      .orderBy("createdAt", "desc")
      .limit(historyCount)
      .select("passwordHash");
    for (const row of history) {
      if (await verifyPassword(input.password, row.passwordHash)) {
        throw new AuthError(`新密码不能与最近 ${historyCount} 个历史密码重复`, 409, { code: "PASSWORD_REUSED" });
      }
    }
  }

  const timestamp = nextMonotonicTimestamp(
    [user.updatedAt, user.passwordChangedAt],
    input.timestamp ?? now(),
  );
  const passwordHash = await hashPassword(input.password);
  const updateQuery = (client as any)("o_user")
    .where({ id: input.userId, password: user.password });
  if (user.updatedAt === null || user.updatedAt === undefined) {
    updateQuery.whereNull("updatedAt");
  } else {
    updateQuery.where("updatedAt", user.updatedAt);
  }
  const updated = await updateQuery.update({
    password: passwordHash,
    passwordChangedAt: timestamp,
    updatedAt: timestamp,
  });
  if (Number(updated || 0) !== 1) throw new AuthError("密码已被其他请求修改，请重试", 409);

  if (historyCount > 0 && isPasswordHash(user.password)) {
    await (client as any)("o_user_password_history").insert({
      id: uuid(),
      userId: input.userId,
      passwordHash: user.password,
      createdAt: timestamp,
    });
    const obsolete = await (client as any)("o_user_password_history")
      .where({ userId: input.userId })
      .orderBy("createdAt", "desc")
      .offset(historyCount)
      .select("id");
    if (obsolete.length) {
      await (client as any)("o_user_password_history").whereIn("id", obsolete.map((row: any) => row.id)).delete();
    }
  } else if (historyCount === 0) {
    await (client as any)("o_user_password_history").where({ userId: input.userId }).delete();
  }

  // A password change advances the authentication generation. Revoke every
  // pre-issued reset/challenge/proof so no stale credential can be revived.
  await (client as any)("o_auth_token")
    .where({ userId: input.userId })
    .whereIn("type", [
      PASSWORD_RESET_TOKEN_TYPE,
      PASSWORD_RESET_CLAIM_TYPE,
      "mfa_login_challenge",
      "step_up_proof",
      SESSION_STEP_UP_ASSURANCE_TOKEN_TYPE,
    ])
    .whereNull("usedAt")
    .update({ usedAt: timestamp });
}

export function isPasswordExpired(user: any, policy: PasswordPolicy, timestamp = now()): boolean {
  if (!policy.expireDays) return false;
  const changedAt = Number(user?.passwordChangedAt || user?.createdAt || 0);
  if (!changedAt) return true;
  return changedAt + policy.expireDays * 24 * 60 * 60 * 1000 <= timestamp;
}

export function hashAuthToken(token: string): string {
  return crypto.createHash("sha256").update(token).digest("hex");
}

export const SESSION_STEP_UP_ASSURANCE_TOKEN_TYPE = "session_step_up_assurance";
export const SESSION_STEP_UP_ASSURANCE_FORMAT = "session-step-up-assurance/v1";
const SESSION_STEP_UP_REUSABLE_ROLES = new Set([
  "root",
  "admin",
  "super_admin",
  "finance_operator",
  "finance_manager",
]);

export function canReuseSessionStepUpAssurance(role: unknown): boolean {
  return SESSION_STEP_UP_REUSABLE_ROLES.has(String(role || "").toLowerCase());
}

export function sessionStepUpAssuranceTokenHash(sessionId: string): string {
  return hashAuthToken(`${SESSION_STEP_UP_ASSURANCE_FORMAT}:${String(sessionId || "").trim()}`);
}

export function accountMfaGeneration(row: any): string {
  return `${row?.mfaEnabled ? "enabled" : "disabled"}:${Number(row?.updatedAt || 0)}`;
}

export async function upsertSessionStepUpAssurance(
  client: Knex | Knex.Transaction,
  input: {
    user: any;
    session: any;
    securityRow: any;
    method: "password" | "totp" | "recovery";
  },
): Promise<void> {
  const userId = Number(input.user?.id || 0);
  const sessionId = String(input.session?.id || "").trim();
  const expiresAt = Number(input.session?.expiresAt || 0);
  if (!Number.isSafeInteger(userId) || userId < 1 || !sessionId || !Number.isSafeInteger(expiresAt)) {
    throw new AuthError("登录会话无法建立管理员操作授权", 401, {
      code: "SESSION_STEP_UP_ASSURANCE_INVALID",
    });
  }
  const securityEnabled = Boolean(input.securityRow?.mfaEnabled);
  if (securityEnabled && input.method === "password") {
    throw new AuthError("当前登录尚未完成 MFA 验证", 401, {
      code: "SESSION_STEP_UP_ASSURANCE_INVALID",
    });
  }
  if (!securityEnabled && input.method !== "password") {
    throw new AuthError("当前登录的 MFA 状态已变化", 401, {
      code: "SESSION_STEP_UP_ASSURANCE_INVALID",
    });
  }
  const authorizationRevision = Number(input.user.authorizationRevision ?? 1);
  const timestamp = now();
  const tokenHash = sessionStepUpAssuranceTokenHash(sessionId);
  const row = {
    userId,
    workspaceId: input.session.workspaceId ?? null,
    tokenHash,
    type: SESSION_STEP_UP_ASSURANCE_TOKEN_TYPE,
    metadata: JSON.stringify({
      format: SESSION_STEP_UP_ASSURANCE_FORMAT,
      sessionId,
      passwordVersion: hashAuthToken(String(input.user.password || "")),
      mfaGeneration: accountMfaGeneration(input.securityRow),
      authorizationRevision,
      method: input.method,
    }),
    expiresAt,
    usedAt: null,
    createdAt: timestamp,
  };
  const existing = await (client as any)("o_auth_token")
    .where({ tokenHash, type: SESSION_STEP_UP_ASSURANCE_TOKEN_TYPE })
    .first();
  if (existing) {
    await (client as any)("o_auth_token")
      .where({ id: existing.id, tokenHash, type: SESSION_STEP_UP_ASSURANCE_TOKEN_TYPE })
      .update({
        workspaceId: row.workspaceId,
        metadata: row.metadata,
        expiresAt: row.expiresAt,
        usedAt: null,
      });
    return;
  }
  await (client as any)("o_auth_token").insert({ id: uuid(), ...row });
}

export function extractBearerToken(rawToken: unknown): string {
  if (typeof rawToken !== "string") return "";
  return rawToken.replace(/^Bearer\s+/i, "").trim();
}

function publicUser(user: any): Record<string, unknown> {
  return {
    id: Number(user.id),
    name: user.name,
    email: user.email ?? null,
    displayName: user.displayName ?? user.name,
    role: user.role ?? "member",
    status: user.status ?? "active",
    currentWorkspaceId: user.currentWorkspaceId ?? null,
    defaultWorkspaceId: user.defaultWorkspaceId ?? user.currentWorkspaceId ?? null,
    createdAt: user.createdAt ?? null,
    updatedAt: user.updatedAt ?? null,
    lastLoginAt: user.lastLoginAt ?? null,
  };
}

function knownValue<T extends string>(values: readonly T[], value: unknown): T | null {
  const normalized = String(value || "");
  return (values as readonly string[]).includes(normalized) ? normalized as T : null;
}

function buildIdentitySubject(user: any, workspace: any | null): IdentitySubjectV1 {
  const legacyRole = knownValue(
    [...platformRoles, ...financeRoles, ...workspaceRoles, "user"] as const,
    user.role,
  ) as LegacyUserRole | null;
  const platformRole = knownValue(platformRoles, user.role) as PlatformRole | null;
  const financeRole = knownValue(financeRoles, user.role) as FinanceRole | null;
  const workspaceRole = knownValue(workspaceRoles, workspace?.memberRole) as WorkspaceRole | null;
  const userStatus = knownValue(userStatuses, user.status || "active") as UserStatus | null;
  const workspaceStatus = knownValue(workspaceStatuses, workspace?.status) as WorkspaceStatus | null;
  const membershipStatus = knownValue(
    workspaceMemberStatuses,
    workspace?.memberStatus,
  ) as WorkspaceMemberStatus | null;
  const activeWorkspaceContext = (
    userStatus === "active"
    && workspaceStatus === "active"
    && membershipStatus === "active"
    && workspaceRole !== null
  );

  return {
    contractVersion: identityContractVersion,
    userId: Number(user.id),
    // Authentication rejects unknown/non-active users before emitting this
    // DTO. Keep the adapter fail-closed if a legacy caller bypasses auth.
    userStatus: userStatus || "locked",
    legacyRole,
    platformRole,
    financeRole,
    workspaceId: activeWorkspaceContext ? String(workspace.id) : null,
    workspaceStatus: activeWorkspaceContext ? workspaceStatus : null,
    membershipId: activeWorkspaceContext ? String(workspace.memberId) : null,
    membershipStatus: activeWorkspaceContext ? membershipStatus : null,
    workspaceRole: activeWorkspaceContext ? workspaceRole : null,
    platformPermissions: platformRole ? [...getRolePermissions(platformRole)] : [],
    financePermissions: financeRole ? [...getRolePermissions(financeRole)] : [],
    workspacePermissions: activeWorkspaceContext
      ? getEffectiveWorkspacePermissions({
        role: workspaceRole,
        permissions: workspace.memberPermissions,
        permissionsConfigured: workspace.memberPermissionsConfigured,
      })
      : [],
  };
}

async function getTokenKey(knex: Knex): Promise<string> {
  const setting = await knex<any>("o_setting").where("key", "tokenKey").select("value").first();
  if (setting?.value) return String(setting.value);

  // A recovered checkpoint is evidence, so session verification must never
  // repair a missing signing key as a side effect of an untrusted Bearer token.
  if (isRecoveryOnlyMode()) {
    throw new AuthError("认证密钥不可用", 503, {
      code: "AUTH_TOKEN_KEY_UNAVAILABLE",
    });
  }

  const value = uuid().replace(/-/g, "");
  await knex<any>("o_setting").insert({ key: "tokenKey", value });
  return value;
}

function slugify(value: string): string {
  const slug = value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return slug || `workspace-${crypto.randomBytes(4).toString("hex")}`;
}

async function uniqueWorkspaceSlug(knex: Knex, baseValue: string): Promise<string> {
  const base = slugify(baseValue);
  let slug = base;
  let index = 1;
  while (await knex<any>("o_workspace").where("slug", slug).first()) {
    index += 1;
    slug = `${base}-${index}`;
  }
  return slug;
}

export async function getUserWorkspaces(
  knex: Knex,
  userId: number,
  options: { lockAuthority?: boolean } = {},
): Promise<any[]> {
  let workspaceIds: string[] = [];
  if (options.lockAuthority) {
    const candidateRows = await knex<any>("o_workspace_member")
      .where({ userId, status: "active" })
      .select("workspaceId");
    workspaceIds = Array.from(new Set(
      candidateRows.map((row: any) => String(row.workspaceId || "")).filter(Boolean),
    )).sort();
  }
  let workspaceQuery = knex<any>("o_workspace")
    .where({ status: "active" });
  if (options.lockAuthority) {
    if (!workspaceIds.length) return [];
    workspaceQuery = workspaceQuery.whereIn("id", workspaceIds).orderBy("id", "asc").forShare();
  }
  const workspaces = options.lockAuthority
    ? await workspaceQuery.select("*")
    : [];
  if (!options.lockAuthority) {
    const candidateMembers = await knex<any>("o_workspace_member")
      .where({ userId, status: "active" })
      .select("workspaceId");
    workspaceIds = Array.from(new Set(
      candidateMembers.map((row: any) => String(row.workspaceId || "")).filter(Boolean),
    ));
  }
  if (!workspaceIds.length) return [];

  let memberQuery = knex<any>("o_workspace_member")
    .where({ userId, status: "active" })
    .whereIn("workspaceId", workspaceIds);
  if (options.lockAuthority) {
    memberQuery = memberQuery.orderBy("workspaceId", "asc").forShare();
  }
  const members = (await memberQuery.select("*"))
    .filter((member: any) => knownValue(workspaceRoles, member.role) !== null);
  const activeWorkspaces = options.lockAuthority
    ? workspaces
    : await knex<any>("o_workspace")
      .whereIn("id", workspaceIds)
      .where({ status: "active" })
      .select("*");
  return activeWorkspaces.flatMap((workspace: any) => {
    const member = members.find((item: any) => item.workspaceId === workspace.id);
    const memberRole = getConsistentWorkspaceRole({
      userId: member?.userId,
      memberRole: member?.role,
      ownerUserId: workspace.ownerUserId,
    });
    if (!memberRole) return [];
    return [{
      ...workspace,
      memberId: member?.id ?? null,
      memberRole,
      memberStatus: member?.status ?? "active",
      memberPermissions: parseWorkspaceMemberPermissions(member?.permissions),
      memberPermissionsConfigured: member?.permissions !== null && member?.permissions !== undefined,
    }];
  });
}

interface UserWorkspaceInvariant {
  workspaces: any[];
  defaultWorkspaceId: string;
  currentWorkspaceId: string;
}

function defaultPersonalWorkspaceName(user: any): string {
  const suffix = " 的工作区";
  const fallback = "用户";
  const label = String(user?.displayName || user?.name || fallback).trim() || fallback;
  return `${label.slice(0, Math.max(1, 64 - suffix.length))}${suffix}`;
}

/**
 * Keep the account -> default workspace invariant inside the user-row lock.
 *
 * Registration paths create this authority eagerly. This repair path covers
 * legacy/imported rows and partial historical data without relying on a
 * frontend redirect: reuse a valid membership, restore the authoritative
 * owner's mirrored membership, or create one personal workspace exactly once.
 */
async function ensureUserWorkspaceInvariantInTransaction(
  trx: Knex.Transaction,
  user: any,
): Promise<UserWorkspaceInvariant> {
  const userId = Number(user?.id || 0);
  if (!Number.isSafeInteger(userId) || userId < 1) {
    throw new AuthError("账号不可用", 403, { code: "ACCOUNT_UNAVAILABLE" });
  }

  let workspaces = await getUserWorkspaces(trx, userId, { lockAuthority: true });
  if (!workspaces.length) {
    const timestamp = now();
    const ownedWorkspace = await trx<any>("o_workspace")
      .where({ ownerUserId: userId, status: "active" })
      .orderBy("createdAt", "asc")
      .orderBy("id", "asc")
      .forUpdate()
      .first();
    let workspaceId = String(ownedWorkspace?.id || "");

    if (ownedWorkspace) {
      const mirroredMember = await trx<any>("o_workspace_member")
        .where({ workspaceId, userId })
        .forUpdate()
        .first();
      if (mirroredMember) {
        await trx<any>("o_workspace_member").where({ id: mirroredMember.id }).update({
          role: "owner",
          status: "active",
          permissions: null,
          updatedAt: timestamp,
        });
      } else {
        await trx<any>("o_workspace_member").insert({
          id: uuid(),
          workspaceId,
          userId,
          role: "owner",
          status: "active",
          permissions: null,
          createdAt: timestamp,
          updatedAt: timestamp,
        });
      }
    } else {
      workspaceId = uuid();
      const workspaceName = defaultPersonalWorkspaceName(user);
      await trx<any>("o_workspace").insert({
        id: workspaceId,
        name: workspaceName,
        slug: await uniqueWorkspaceSlug(trx, workspaceName),
        ownerUserId: userId,
        status: "active",
        createdAt: timestamp,
        updatedAt: timestamp,
      });
      await trx<any>("o_workspace_member").insert({
        id: uuid(),
        workspaceId,
        userId,
        role: "owner",
        status: "active",
        permissions: null,
        createdAt: timestamp,
        updatedAt: timestamp,
      });
    }

    await ensureWorkspaceBillingAccountRecord(trx, { workspaceId, timestamp });
    workspaces = await getUserWorkspaces(trx, userId, { lockAuthority: true });
  }

  if (!workspaces.length) {
    throw new AuthError("默认工作区创建失败", 500, {
      code: "DEFAULT_WORKSPACE_UNAVAILABLE",
    });
  }

  const defaultWorkspace =
    workspaces.find((item) => item.id === user.defaultWorkspaceId)
    || workspaces.find((item) => item.id === user.currentWorkspaceId)
    || workspaces[0];
  const currentWorkspace =
    workspaces.find((item) => item.id === user.currentWorkspaceId)
    || defaultWorkspace;
  const defaultWorkspaceId = String(defaultWorkspace.id);
  const currentWorkspaceId = String(currentWorkspace.id);

  if (
    String(user.defaultWorkspaceId || "") !== defaultWorkspaceId
    || String(user.currentWorkspaceId || "") !== currentWorkspaceId
  ) {
    await trx<any>("o_user").where({ id: userId }).update({
      defaultWorkspaceId,
      currentWorkspaceId,
      updatedAt: now(),
    });
  }

  return { workspaces, defaultWorkspaceId, currentWorkspaceId };
}

export async function getAuthProfile(knex: Knex, userId: number): Promise<Record<string, unknown>> {
  const user = await knex<any>("o_user").where("id", userId).first();
  if (!user) throw new AuthError("用户不存在", 401);
  const workspaces = await getUserWorkspaces(knex, Number(user.id));
  const workspace =
    workspaces.find((item) => item.id === user.currentWorkspaceId) || workspaces[0] || null;
  const userRole = String(user.role || "");
  const displayRole = ["root", "admin", "super_admin"].includes(userRole)
    ? userRole
    : workspace?.memberRole || user.role || "member";
  const identity = buildIdentitySubject(user, workspace);

  return {
    user: publicUser(user),
    workspace,
    workspaces,
    role: displayRole,
    permissions: workspace
      ? getEffectiveWorkspacePermissions({
          role: String(workspace.memberRole || ""),
          permissions: workspace.memberPermissions,
          permissionsConfigured: workspace.memberPermissionsConfigured,
        })
      : [],
    identity,
    platformAccess: {
      role: identity.platformRole ?? identity.financeRole ?? null,
      effectivePermissions: [
        ...identity.platformPermissions,
        ...identity.financePermissions,
      ],
    },
  };
}

export async function createPasswordResetToken(
  knex: Knex,
  usernameOrEmail: string,
  authInfo: RequestAuthInfo = {},
): Promise<Record<string, unknown>> {
  const identifier = usernameOrEmail.trim();
  if (!identifier) throw new AuthError("请输入用户名或邮箱");
  const user = await findUserForLogin(knex, identifier);
  const timestamp = now();
  await enforcePasswordResetRequestRateLimit(knex, {
    identifier,
    userId: user?.id ? Number(user.id) : null,
    ip: authInfo.ip,
    timestamp,
  });
  const mailReady = await isMailConfigured();
  const publicBaseUrl = resolvePasswordResetPublicBaseUrl();
  if (!mailReady) {
    throw new AuthError("邮件服务未配置，请联系管理员", 503, { code: "MAIL_NOT_CONFIGURED" });
  }
  if (!publicBaseUrl) {
    throw new AuthError("邮件服务未配置，请联系管理员", 503, { code: "MAIL_NOT_CONFIGURED" });
  }

  const publicResult: Record<string, unknown> = {
    issued: true,
    expiresAt: timestamp + PASSWORD_RESET_TTL_MS,
    delivery: "email",
  };

  if (!user || (user.status && user.status !== "active")) {
    return publicResult;
  }
  if (!user.email || !user.emailVerifiedAt) {
    return publicResult;
  }

  const handoff = createAuthHandoffIssue({
    flow: "password_reset",
    publicBaseUrl,
    seed: authInfo.handoffSeed,
  });
  const issued = await knex.transaction(async (trx) => {
    // Global auth lock order: user first, then password-reset family.
    const lockedUser = await trx<any>("o_user")
      .where({ id: Number(user.id) })
      .forUpdate()
      .first();
    if (!lockedUser || String(lockedUser.status || "") !== "active") return null;
    const lockedEmail = String(lockedUser.email || "").trim();
    if (!lockedEmail || !lockedUser.emailVerifiedAt) return null;

    await lockPasswordResetTokenFamily(trx, Number(lockedUser.id));
    const issuedAt = now();
    const expiresAt = issuedAt + PASSWORD_RESET_TTL_MS;
    await markUnusedPasswordResetFamilyUsed(trx, Number(lockedUser.id), issuedAt);
    await trx<any>("o_auth_token").insert({
      id: handoff.locator,
      userId: Number(lockedUser.id),
      workspaceId: lockedUser.currentWorkspaceId ?? null,
      tokenHash: handoff.codeMac,
      type: PASSWORD_RESET_TOKEN_TYPE,
      metadata: JSON.stringify({
        userAgent: authInfo.userAgent ?? null,
        ip: authInfo.ip ?? null,
        email: String(lockedUser.email || "").trim().toLowerCase() || null,
        passwordVersion: hashAuthToken(String(lockedUser.password || "")),
        authVersion: Number(lockedUser.updatedAt || 0),
        handoffVersion: 2,
        seedHash: authInfo.handoffSeed
          ? authHandoffSeedHash(authInfo.handoffSeed)
          : null,
        failedAttempts: 0,
      }),
      expiresAt,
      usedAt: null,
      createdAt: issuedAt,
    });
    return {
      email: lockedEmail,
      username: String(lockedUser.name || identifier),
      expiresAt,
    };
  });
  if (!issued) return publicResult;
  publicResult.expiresAt = issued.expiresAt;

  if (mailReady && issued.email) {
    try {
      await deliverPasswordResetEmail({
        email: issued.email,
        username: issued.username,
        resetUrl: handoff.url,
        code: handoff.code,
      });
    } catch (err: any) {
      await knex.transaction(async (trx) => {
        await trx<any>("o_user").where({ id: Number(user.id) }).forUpdate().first();
        await lockPasswordResetTokenFamily(trx, Number(user.id));
        await trx<any>("o_auth_token")
          .where({
            userId: Number(user.id),
            type: PASSWORD_RESET_TOKEN_TYPE,
            id: handoff.locator,
          })
          .whereNull("usedAt")
          .update({ usedAt: now() });
      });
      console.error("[auth] password reset delivery failed", err?.message || err);
      throw new AuthError("密码重置邮件投递失败，请稍后重试", 502, { code: "MAIL_DELIVERY_FAILED" });
    }
  }

  return { ...publicResult };
}

export async function resetPasswordWithToken(
  _knex: Knex,
  _token: string,
  _password: string,
): Promise<Record<string, unknown>> {
  throw new AuthError("旧版邮件链接已停用，请重新申请", 410, {
    code: "AUTH_LINK_LEGACY_GONE",
  });
}

export async function completePasswordResetHandoff(
  knex: Knex,
  claim: string,
  password: string,
): Promise<Record<string, unknown>> {
  return await consumeAuthHandoffClaim(knex, {
    flow: "password_reset",
    claim,
    async consume(trx, user, metadata, consumedAt) {
      const passwordVersion = String(metadata.passwordVersion || "");
      const authVersion = Number(metadata.authVersion);
      const currentEmail = String(user.email || "").trim().toLowerCase() || null;
      const metadataEmail = typeof metadata.email === "string"
        ? String(metadata.email).trim().toLowerCase()
        : null;
      if (
        !passwordVersion
        || passwordVersion !== hashAuthToken(String(user.password || ""))
        || !Number.isFinite(authVersion)
        || authVersion !== Number(user.updatedAt || 0)
        || metadataEmail !== currentEmail
      ) {
        throw new AuthError("重置凭据已失效，请重新申请", 400, {
          code: "PASSWORD_RESET_CREDENTIAL_CHANGED",
        });
      }
      const security = await getAccountSecurityPolicy(trx, Number(user.id));
      const passwordError = validatePasswordAgainstPolicy(password, security.passwordPolicy);
      if (passwordError) throw new AuthError(passwordError);
      await updatePasswordWithHistory(trx, {
        userId: Number(user.id),
        password,
        policy: security.passwordPolicy,
        timestamp: consumedAt,
      });
      await trx<any>("o_user_session")
        .where({ userId: Number(user.id) })
        .whereNull("revokedAt")
        .update({ revokedAt: consumedAt, updatedAt: consumedAt });
      return { reset: true, userId: Number(user.id) };
    },
  });
}

const MAX_OWNED_WORKSPACES = Math.max(1, Number(process.env.FANJIN_MAX_OWNED_WORKSPACES || 10));

export async function createWorkspaceInTransaction(
  trx: Knex.Transaction,
  input: {
    userId: number;
    name: string;
    switchTo?: boolean;
    sessionId?: string | null;
  },
): Promise<{ workspaceId: string }> {
  const name = String(input.name || "").trim();
  if (!name) throw new AuthError("工作区名称不能为空");
  if (name.length > 64) throw new AuthError("工作区名称过长");
  const userId = Number(input.userId || 0);
  if (!userId) throw new AuthError("未登录", 401);

  // Serialize all workspace creation authority and owned-workspace quota for
  // this user. The user row is the first lock in the global identity order.
  const user = await trx<any>("o_user")
    .where({ id: userId })
    .forUpdate()
    .first();
  if (!user || user.status !== "active") {
    throw new AuthError("账号不可用", 403, { code: "ACCOUNT_UNAVAILABLE" });
  }

  const ownedCountRow = await trx<any>("o_workspace")
    .where({ ownerUserId: userId, status: "active" })
    .count({ count: "id" })
    .first();
  if (Number(ownedCountRow?.count || 0) >= MAX_OWNED_WORKSPACES) {
    throw new AuthError(`最多只能创建 ${MAX_OWNED_WORKSPACES} 个工作区`, 409);
  }

  const timestamp = now();
  const workspaceId = uuid();
  const slug = await uniqueWorkspaceSlug(trx as any, name);
  await trx<any>("o_workspace").insert({
    id: workspaceId,
    name,
    slug,
    ownerUserId: userId,
    status: "active",
    createdAt: timestamp,
    updatedAt: timestamp,
  });
  await trx<any>("o_workspace_member").insert({
    id: uuid(),
    workspaceId,
    userId,
    role: "owner",
    status: "active",
    permissions: null,
    createdAt: timestamp,
    updatedAt: timestamp,
  });
  if (!user.defaultWorkspaceId) {
    await trx<any>("o_user").where("id", userId).update({
      defaultWorkspaceId: workspaceId,
      updatedAt: timestamp,
    });
  }

  if (input.switchTo !== false) {
    await trx<any>("o_user").where("id", userId).update({
      currentWorkspaceId: workspaceId,
      updatedAt: timestamp,
    });
    if (input.sessionId) {
      const updated = await trx<any>("o_user_session")
        .where({ id: input.sessionId, userId })
        .whereNull("revokedAt")
        .update({
          workspaceId,
          updatedAt: timestamp,
          lastSeenAt: timestamp,
        });
      if (Number(updated || 0) !== 1) {
        throw new AuthError("会话已失效", 401, { code: "SESSION_REVOKED" });
      }
    }
  }

  return { workspaceId };
}

export async function createWorkspace(
  knex: Knex,
  input: {
    userId: number;
    name: string;
    switchTo?: boolean;
    sessionId?: string | null;
  },
): Promise<Record<string, unknown>> {
  const userId = Number(input.userId || 0);
  await knex.transaction(async (trx) => {
    await createWorkspaceInTransaction(trx, input);
  });
  return await getAuthProfile(knex, userId);
}

export async function switchWorkspace(
  knex: Knex,
  userId: number,
  workspaceId: string,
  sessionId?: string | null,
): Promise<Record<string, unknown>> {
  const timestamp = now();
  await knex.transaction(async (trx) => {
    const user = await trx<any>("o_user")
      .where({ id: userId })
      .forUpdate()
      .first();
    if (!user || user.status !== "active") {
      throw new AuthError("账号不可用", 403, { code: "ACCOUNT_UNAVAILABLE" });
    }
    const workspace = await trx<any>("o_workspace")
      .where({ id: workspaceId, status: "active" })
      .forShare()
      .first();
    if (!workspace) throw new AuthError("无权访问该工作区", 403);
    const member = await trx<any>("o_workspace_member")
      .where({ userId, workspaceId, status: "active" })
      .forShare()
      .first();
    const memberRole = member
      ? getConsistentWorkspaceRole({
        userId: member.userId,
        memberRole: member.role,
        ownerUserId: workspace.ownerUserId,
      })
      : null;
    if (!memberRole) throw new AuthError("无权访问该工作区", 403);

    await trx<any>("o_user").where("id", userId).update({
      currentWorkspaceId: workspaceId,
      updatedAt: timestamp,
    });
    if (sessionId) {
      const updated = await trx<any>("o_user_session")
        .where({ id: sessionId, userId })
        .whereNull("revokedAt")
        .update({ workspaceId, updatedAt: timestamp, lastSeenAt: timestamp });
      if (Number(updated || 0) !== 1) {
        throw new AuthError("会话已失效", 401, { code: "SESSION_REVOKED" });
      }
    }
  });

  return await getAuthProfile(knex, userId);
}

async function findUserForLogin(knex: Knex, username: string): Promise<any | null> {
  const normalized = username.trim();
  if (!normalized) return null;

  const user = await knex<any>("o_user")
    .where("name", normalized)
    .orWhere("email", normalized)
    .first();
  if (user) return user;

  if (normalized === "admin") {
    return await knex<any>("o_user").where("name", "root").first();
  }
  return null;
}

export async function enforceSessionPolicy(
  knex: Knex,
  session: any,
  timestamp = now(),
  options: { touch?: boolean; revokeExpired?: boolean } = {},
): Promise<any> {
  const security = await getAccountSecurityPolicy(knex, Number(session.userId));
  const absoluteLifetimeMs = security.sessionPolicy.absoluteHours * 60 * 60 * 1000;
  const idleLifetimeMs = security.sessionPolicy.idleMinutes * 60 * 1000;
  const createdAt = Number(session.createdAt || 0);
  const lastSeenAt = Number(session.lastSeenAt || createdAt);
  const configuredAbsoluteExpiry = createdAt + absoluteLifetimeMs;
  const storedExpiry = Number(session.expiresAt || configuredAbsoluteExpiry);
  const absoluteExpiry = Math.min(storedExpiry, configuredAbsoluteExpiry);
  const idleExpiry = lastSeenAt + idleLifetimeMs;

  if (!createdAt || absoluteExpiry <= timestamp || idleExpiry <= timestamp) {
    if (options.revokeExpired !== false) {
      await knex<any>("o_user_session")
        .where({ id: session.id })
        .whereNull("revokedAt")
        .update({ revokedAt: timestamp, updatedAt: timestamp });
    }
    const reason = absoluteExpiry <= timestamp ? "会话已超过最长有效期" : "会话已因长时间未操作失效";
    throw new AuthError(reason, 401, { code: "SESSION_EXPIRED" });
  }

  if (options.touch === false) {
    return {
      ...session,
      expiresAt: absoluteExpiry,
    };
  }

  const touched = await knex<any>("o_user_session")
    .where({ id: session.id, tokenHash: session.tokenHash })
    .whereNull("revokedAt")
    .update({ lastSeenAt: timestamp, updatedAt: timestamp });
  if (!Number(touched || 0)) throw new AuthError("无效的token", 401);
  return { ...session, expiresAt: absoluteExpiry, lastSeenAt: timestamp, updatedAt: timestamp };
}

export async function createSession(knex: Knex, user: any, authInfo: RequestAuthInfo = {}): Promise<Record<string, unknown>> {
  const userId = Number(user?.id || 0);
  if (!Number.isSafeInteger(userId) || userId < 1) {
    throw new AuthError("账号不可用", 403, { code: "ACCOUNT_UNAVAILABLE" });
  }
  const create = async (trx: Knex.Transaction) => {
    const liveUser = await trx<any>("o_user")
      .where({ id: userId })
      .forUpdate()
      .first();
    if (!liveUser || liveUser.status !== "active") {
      throw new AuthError("账号不可用", 403, { code: "ACCOUNT_UNAVAILABLE" });
    }
    const workspaceAuthority = await ensureUserWorkspaceInvariantInTransaction(trx, liveUser);
    const workspaces = workspaceAuthority.workspaces;
    const workspace =
      workspaces.find((item) => item.id === workspaceAuthority.currentWorkspaceId)
      || workspaces[0]
      || null;
    const workspaceId = workspace?.id ?? null;
    const sessionId = uuid();
    const tokenKey = await getTokenKey(trx);
    const security = await getAccountSecurityPolicy(trx, userId);
    const securityRow = await trx<any>("o_account_security")
      .where({ userId })
      .forShare()
      .first();
    const sessionTtlMs = security.sessionPolicy.absoluteHours * 60 * 60 * 1000;
    const payload: AuthTokenPayload = {
      id: userId,
      name: liveUser.name,
      role: liveUser.role ?? "member",
      workspaceId,
      sid: sessionId,
    };
    const rawToken = (jwt.sign as any)(payload, tokenKey, {
      expiresIn: Math.max(60, Math.floor(sessionTtlMs / 1000)),
    });
    const timestamp = now();

    const session = {
      id: sessionId,
      userId,
      workspaceId,
      tokenHash: hashAuthToken(rawToken),
      userAgent: authInfo.userAgent ?? null,
      ip: authInfo.ip ?? null,
      expiresAt: timestamp + sessionTtlMs,
      revokedAt: null,
      createdAt: timestamp,
      updatedAt: timestamp,
      lastSeenAt: timestamp,
    };
    await trx<any>("o_user_session").insert(session);
    if (authInfo.stepUpMethod && canReuseSessionStepUpAssurance(liveUser.role)) {
      await upsertSessionStepUpAssurance(trx, {
        user: liveUser,
        session,
        securityRow,
        method: authInfo.stepUpMethod,
      });
    }
    await trx<any>("o_user").where("id", userId).update({
      currentWorkspaceId: workspaceId,
      lastLoginAt: timestamp,
      updatedAt: timestamp,
    });
    return { rawToken, sessionId };
  };

  const created = (knex as any).isTransaction
    ? await create(knex as Knex.Transaction)
    : await knex.transaction(create);
  const profile = await getAuthProfile(knex, userId);
  return {
    token: `Bearer ${created.rawToken}`,
    rawToken: created.rawToken,
    sessionId: created.sessionId,
    ...profile,
  };
}

export async function resolveSessionFromAuthorization(
  knex: Knex,
  authorization: unknown,
  options: {
    touchSession?: boolean;
    revokeExpiredSession?: boolean;
  } = {},
): Promise<Record<string, unknown> | null> {
  const rawToken = extractBearerToken(authorization);
  if (!rawToken) return null;

  const tokenKey = await getTokenKey(knex);
  let decoded: AuthTokenPayload;
  try {
    decoded = jwt.verify(rawToken, tokenKey) as AuthTokenPayload;
  } catch {
    throw new AuthError("无效的token", 401);
  }
  if (!decoded?.sid) throw new AuthError("token已失效，请重新登录", 401);

  let session = await knex<any>("o_user_session")
    .where("id", decoded.sid)
    .where("tokenHash", hashAuthToken(rawToken))
    .first();
  if (!session || session.revokedAt) throw new AuthError("无效的token", 401);
  if (Number(session.userId) !== Number(decoded.id)) {
    throw new AuthError("无效的token", 401);
  }
  if (session.expiresAt && Number(session.expiresAt) < Date.now()) throw new AuthError("token已过期", 401);
  session = await enforceSessionPolicy(knex, session, now(), {
    touch: options.touchSession !== false,
    revokeExpired: options.revokeExpiredSession !== false,
  });

  const user = await knex<any>("o_user").where("id", Number(decoded.id)).first();
  if (!user || user.status !== "active") throw new AuthError("账号不可用", 401);
  // Only the server-owned session row can select a workspace. JWT and the
  // user's mutable convenience pointer are never authorization fallbacks.
  const requestedWorkspaceId = String(session.workspaceId || "").trim();
  const activeWorkspaceContext = requestedWorkspaceId
    ? await knex<any>("o_workspace_member as member")
      .innerJoin("o_workspace as workspace", "workspace.id", "member.workspaceId")
      .where({
        "member.workspaceId": requestedWorkspaceId,
        "member.userId": Number(user.id),
        "member.status": "active",
        "workspace.status": "active",
      })
      .select(
        "member.id",
        "member.userId",
        "member.role",
        "workspace.ownerUserId as workspaceOwnerUserId",
      )
      .first()
    : null;
  const activeWorkspaceRole = activeWorkspaceContext
    ? getConsistentWorkspaceRole({
      userId: activeWorkspaceContext.userId,
      memberRole: activeWorkspaceContext.role,
      ownerUserId: activeWorkspaceContext.workspaceOwnerUserId,
    })
    : null;
  const activeWorkspaceAuthority = (
    activeWorkspaceContext
    && (
      knownValue(platformRoles, user.role) !== null
      || activeWorkspaceRole !== null
    )
    && activeWorkspaceRole !== null
  );

  return {
    rawToken,
    payload: decoded,
    session,
    user,
    // A stale JWT/session workspace is only a locator. Suspended workspaces
    // and disabled memberships lose authority on the very next request.
    workspaceId: activeWorkspaceAuthority ? requestedWorkspaceId : null,
  };
}

/**
 * Deliberate, operator-opt-in bypass of password verification. This mints a
 * real session for the platform root account using the exact same
 * createSession() path as a normal login, so every downstream workspace/
 * billing/permission check keeps working unchanged. It must stay disabled
 * unless the operator explicitly sets FANJIN_ENABLE_AUTO_LOGIN=1 — callers
 * (the HTTP route) are responsible for that gate; this function only
 * implements the credential-free session issuance itself.
 */
export async function autoLoginAsPlatformRoot(
  knex: Knex,
  authInfo: RequestAuthInfo = {},
): Promise<Record<string, unknown>> {
  const user = await knex<any>("o_user")
    .whereRaw("lower(role) = ?", ["root"])
    .andWhere({ status: "active" })
    .orderBy("id", "asc")
    .first();
  if (!user) {
    throw new AuthError("未找到可用的管理员账号，无法自动登录", 503, { code: "AUTO_LOGIN_UNAVAILABLE" });
  }
  const session = await createSession(knex, user, authInfo);
  return {
    ...session,
    security: { mustChangePassword: false },
  };
}

export async function loginWithPassword(
  knex: Knex,
  username: string,
  password: string,
  authInfo: RequestAuthInfo = {},
): Promise<Record<string, unknown>> {
  type LoginLimit = ReturnType<typeof effectiveLoginLimit>;
  const attemptedAt = now();
  const userSnapshot = await findUserForLogin(knex, username);
  const securitySnapshot = await getAccountSecurityPolicy(knex, Number(userSnapshot?.id || 0));
  const identityHash = loginIdentityHash(userSnapshot?.id, username);
  const ipIdentityHash = loginIpIdentityHash(authInfo.ip || "");
  const loginLimit = effectiveLoginLimit(securitySnapshot);
  const ipLoginLimit = effectiveIpLoginLimit();
  const currentLimit = await checkLoginLimit(knex, identityHash, loginLimit, attemptedAt);
  const currentIpLimit = await checkLoginLimit(knex, ipIdentityHash, ipLoginLimit, attemptedAt);
  const currentBlock = currentLimit.blocked ? currentLimit : currentIpLimit;
  if (currentBlock.blocked) {
    throw new AuthError("登录尝试过多，请稍后重试", 429, {
      code: "LOGIN_LOCKED",
      retryAfterSeconds: currentBlock.retryAfterSeconds,
    });
  }

  const recordFailedCredential = async (
    effectiveLimit: LoginLimit = loginLimit,
  ): Promise<void> => {
    const failed = await recordLoginFailure(knex, {
      identityHash,
      userId: userSnapshot?.id ? Number(userSnapshot.id) : null,
      limit: effectiveLimit,
      timestamp: attemptedAt,
    });
    const failedIp = await recordLoginFailure(knex, {
      identityHash: ipIdentityHash,
      userId: null,
      limit: ipLoginLimit,
      timestamp: attemptedAt,
    });
    const block = failed.blocked ? failed : failedIp;
    if (block.blocked) {
      throw new AuthError("登录尝试过多，请稍后重试", 429, {
        code: "LOGIN_LOCKED",
        retryAfterSeconds: block.retryAfterSeconds,
      });
    }
  };

  if (!userSnapshot) {
    await recordFailedCredential();
    throw new AuthError("用户名或密码错误");
  }
  const normalizedUsername = String(username || "").trim();
  type LoginOutcome =
    | { kind: "invalid"; limit: LoginLimit }
    | {
      kind: "mfa";
      challenge: Awaited<ReturnType<typeof issueMfaLoginChallenge>>;
      mustChangePassword: boolean;
    }
    | {
      kind: "session";
      session: Record<string, unknown>;
      mustChangePassword: boolean;
    };

  const outcome = await knex.transaction<LoginOutcome>(async (trx) => {
    // Password verification and credential/session creation share one
    // user-first critical section. A reset/change that commits first is seen
    // here; one that starts later waits until this login outcome commits.
    const user = await trx<any>("o_user")
      .where({ id: Number(userSnapshot.id) })
      .forUpdate()
      .first();
    const principalStillMatches = Boolean(
      user
      && (
        String(user.name || "") === normalizedUsername
        || String(user.email || "") === normalizedUsername
        || (normalizedUsername === "admin" && String(user.name || "") === "root")
      ),
    );
    const security = await getAccountSecurityPolicy(trx, Number(user?.id || 0));
    const liveLoginLimit = effectiveLoginLimit(security);
    if (!user || !principalStillMatches) {
      return { kind: "invalid", limit: liveLoginLimit };
    }
    if (user.status && user.status !== "active") {
      throw new AuthError("账号已被禁用", 403);
    }

    const passwordOk = await verifyPassword(password, user.password);
    if (!passwordOk) {
      return { kind: "invalid", limit: liveLoginLimit };
    }

    if (user.email && !user.emailVerifiedAt) {
      throw new AuthError("请先完成邮箱验证", 403, {
        code: "EMAIL_NOT_VERIFIED",
        data: { canResendVerification: true },
      });
    }

    const limitAfterPasswordCheck = await checkLoginLimit(
      trx,
      identityHash,
      liveLoginLimit,
    );
    const ipLimitAfterPasswordCheck = await checkLoginLimit(
      trx,
      ipIdentityHash,
      ipLoginLimit,
    );
    const blockAfterPasswordCheck = limitAfterPasswordCheck.blocked
      ? limitAfterPasswordCheck
      : ipLimitAfterPasswordCheck;
    if (blockAfterPasswordCheck.blocked) {
      throw new AuthError("登录尝试过多，请稍后重试", 429, {
        code: "LOGIN_LOCKED",
        retryAfterSeconds: blockAfterPasswordCheck.retryAfterSeconds,
      });
    }

    if (isPasswordExpired(user, security.passwordPolicy, attemptedAt)) {
      throw new AuthError(
        "密码已过期，请通过密码重置流程设置新密码",
        403,
        { code: "PASSWORD_EXPIRED" },
      );
    }

    if (security.loginIpAllowlist) {
      let ipAllowed = false;
      try {
        ipAllowed = isLoginIpAllowed(authInfo.ip || "", security.loginIpAllowlist);
      } catch {
        throw new AuthError(
          "账号登录安全策略配置无效，请联系管理员",
          503,
          { code: "LOGIN_POLICY_INVALID" },
        );
      }
      if (!ipAllowed) {
        throw new AuthError(
          "当前网络不允许登录此账号",
          403,
          { code: "LOGIN_IP_NOT_ALLOWED" },
        );
      }
    }

    const mustChangePassword = password === "admin123"
      && ["root", "admin"].includes(
        String(user.role || user.name || "").toLowerCase(),
      );

    let authUser = user;
    if (!isPasswordHash(user.password)) {
      const passwordHash = await hashPassword(password);
      const timestamp = Math.max(now(), Number(user.updatedAt || 0) + 1);
      const rehashed = await trx<any>("o_user")
        .where({ id: Number(user.id), password: user.password })
        .update({
          password: passwordHash,
          passwordChangedAt: timestamp,
          updatedAt: timestamp,
        });
      if (Number(rehashed || 0) !== 1) {
        throw new AuthError(
          "密码状态已变化，请重新登录",
          409,
          { code: "AUTH_CREDENTIAL_CHANGED" },
        );
      }
      authUser = {
        ...user,
        password: passwordHash,
        passwordChangedAt: timestamp,
        updatedAt: timestamp,
      };
    }

    if (security.mfaEnabled) {
      try {
        const challenge = await issueMfaLoginChallenge(trx as Knex, {
          userId: Number(authUser.id),
          workspaceId: authUser.currentWorkspaceId ?? null,
          userAgent: authInfo.userAgent,
          ip: authInfo.ip,
          passwordVersion: hashAuthToken(String(authUser.password || "")),
          mustChangePassword,
        });
        return { kind: "mfa", challenge, mustChangePassword };
      } catch (error) {
        if (error instanceof MfaError) {
          throw new AuthError(error.message, error.status, { code: error.code });
        }
        throw error;
      }
    }

    const session = await createSession(trx as Knex, authUser, {
      ...authInfo,
      stepUpMethod: "password",
    });
    return { kind: "session", session, mustChangePassword };
  });

  if (outcome.kind === "invalid") {
    await recordFailedCredential(outcome.limit);
    throw new AuthError("用户名或密码错误");
  }
  if (outcome.kind === "mfa") {
    throw new AuthError("请输入 MFA 验证码或恢复码完成登录", 401, {
      code: "MFA_REQUIRED",
      data: outcome.challenge,
    });
  }

  await clearLoginFailures(knex, identityHash, attemptedAt);
  return {
    ...outcome.session,
    security: {
      mustChangePassword: outcome.mustChangePassword,
    },
  };
}

function parseAuthTokenMetadata(raw: unknown): Record<string, unknown> {
  if (raw && typeof raw === "object" && !Array.isArray(raw)) return raw as Record<string, unknown>;
  if (typeof raw !== "string" || !raw) return {};
  try {
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed as Record<string, unknown> : {};
  } catch {
    return {};
  }
}

export async function loginWithMfaChallenge(
  knex: Knex,
  challenge: string,
  credential: string,
  authInfo: RequestAuthInfo = {},
): Promise<Record<string, unknown>> {
  const rawChallenge = String(challenge || "").trim();
  if (!rawChallenge) throw new AuthError("MFA challenge 不能为空", 400, { code: "MFA_CHALLENGE_INVALID" });
  const candidate = await readMfaLoginChallenge(knex, rawChallenge);
  if (!candidate || !Number(candidate.userId)) {
    throw new AuthError("MFA challenge 无效或已使用", 401, { code: "MFA_CHALLENGE_INVALID" });
  }

  const outcome = await knex.transaction(async (trx) => {
    // Global auth lock order: user -> account security -> challenge family.
    const user = await trx<any>("o_user")
      .where({ id: Number(candidate.userId) })
      .forUpdate()
      .first();
    if (!user || String(user.status || "") !== "active") {
      return { error: new AuthError("账号不可用", 403, { code: "ACCOUNT_UNAVAILABLE" }) };
    }
    const securityRow = await trx<any>("o_account_security")
      .where({ userId: Number(user.id) })
      .forUpdate()
      .first();
    const family = await trx<any>("o_auth_token")
      .where({ userId: Number(user.id), type: "mfa_login_challenge" })
      .orderBy("createdAt", "asc")
      .orderBy("id", "asc")
      .forUpdate()
      .select("*");
    const current = family.find((item: any) => (
      String(item.id) === String(candidate.id)
      && String(item.tokenHash) === String(candidate.tokenHash)
      && item.usedAt === null
    ));
    if (!current) {
      return { error: new AuthError("MFA challenge 无效或已使用", 401, { code: "MFA_CHALLENGE_INVALID" }) };
    }
    const timestamp = now();
    const consumeChallengeFamily = async () => {
      await trx<any>("o_auth_token")
        .where({ userId: Number(user.id), type: "mfa_login_challenge" })
        .whereNull("usedAt")
        .update({ usedAt: timestamp });
    };
    if (Number(current.expiresAt || 0) <= timestamp) {
      await consumeChallengeFamily();
      return {
        error: new AuthError("MFA challenge 已过期", 401, {
          code: "MFA_CHALLENGE_EXPIRED",
        }),
      };
    }

    const security = await getAccountSecurityPolicy(trx, Number(user.id));
    const identityLimit = effectiveLoginLimit(security);
    const ipLimit = effectiveIpLoginLimit();
    const accountIdentityHash = loginIdentityHash(Number(user.id), String(user.name || ""));
    const ipIdentity = loginIpIdentityHash(authInfo.ip || "");
    const accountLimit = await checkLoginLimit(trx, accountIdentityHash, identityLimit, timestamp);
    const currentIpLimit = await checkLoginLimit(trx, ipIdentity, ipLimit, timestamp);
    const activeBlock = accountLimit.blocked ? accountLimit : currentIpLimit;
    if (activeBlock.blocked) {
      await consumeChallengeFamily();
      return {
        error: new AuthError("登录尝试过多，请稍后重试", 429, {
          code: "LOGIN_LOCKED",
          retryAfterSeconds: activeBlock.retryAfterSeconds,
        }),
      };
    }

    const metadata = parseAuthTokenMetadata(current.metadata);
    const expectedIp = String(metadata.ip || "");
    if (expectedIp && expectedIp !== String(authInfo.ip || "")) {
      await consumeChallengeFamily();
      return { error: new AuthError("MFA challenge 请求上下文不匹配", 401, { code: "MFA_CHALLENGE_CONTEXT_MISMATCH" }) };
    }
    const expectedPasswordVersion = String(metadata.passwordVersion || "");
    const expectedAuthGeneration = Number(metadata.authGeneration);
    const expectedMfaGeneration = String(metadata.mfaGeneration || "");
    const currentMfaGeneration = `${securityRow?.mfaEnabled ? "enabled" : "disabled"}:${Number(securityRow?.updatedAt || 0)}`;
    if (
      !expectedPasswordVersion
      || expectedPasswordVersion !== hashAuthToken(String(user.password || ""))
      || !Number.isFinite(expectedAuthGeneration)
      || expectedAuthGeneration !== Number(user.updatedAt || 0)
      || !securityRow?.mfaEnabled
      || expectedMfaGeneration !== currentMfaGeneration
    ) {
      await consumeChallengeFamily();
      return { error: new AuthError("密码状态已变化，请重新登录", 401, { code: "MFA_CHALLENGE_INVALID" }) };
    }

    let verified: Awaited<ReturnType<typeof verifyMfaCredential>>;
    try {
      verified = await verifyMfaCredential(trx, {
        userId: Number(user.id),
        credential,
        totpReplayDomain: "login-session",
      });
    } catch (error) {
      await consumeChallengeFamily();
      if (error instanceof MfaError) {
        return { error: new AuthError(error.message, error.status, { code: error.code }) };
      }
      throw error;
    }
    await consumeChallengeFamily();
    if (!verified.valid) {
      const failed = await recordLoginFailure(trx, {
        identityHash: accountIdentityHash,
        userId: Number(user.id),
        limit: identityLimit,
        timestamp,
      });
      const failedIp = await recordLoginFailure(trx, {
        identityHash: ipIdentity,
        userId: null,
        limit: ipLimit,
        timestamp,
      });
      const block = failed.blocked ? failed : failedIp;
      if (block.blocked) {
        return {
          error: new AuthError("登录尝试过多，请稍后重试", 429, {
            code: "LOGIN_LOCKED",
            retryAfterSeconds: block.retryAfterSeconds,
          }),
        };
      }
      return { error: new AuthError("MFA 验证码或恢复码错误", 401, { code: "MFA_CODE_INVALID" }) };
    }
    await clearLoginFailures(trx, accountIdentityHash, timestamp);
    return {
      session: {
        ...(await createSession(trx, user, {
          ...authInfo,
          stepUpMethod: verified.method || undefined,
        })),
        security: { mustChangePassword: Boolean(metadata.mustChangePassword) },
      },
    };
  });
  if (outcome.error) throw outcome.error;
  if (!outcome.session) throw new AuthError("MFA 登录失败", 401, { code: "MFA_CHALLENGE_INVALID" });
  return outcome.session;
}

export async function registerAccount(
  knex: Knex,
  input: {
    username?: string;
    name?: string;
    email?: string;
    password?: string;
    workspaceName?: string;
    registrationTenant?: {
      tenantId: string;
      hostname?: string | null;
      source?: "public_signup" | "admin_create" | "import";
    };
  },
  authInfo: RequestAuthInfo = {},
): Promise<Record<string, unknown>> {
  const emailNormalized = String(input.email || "").trim().toLowerCase();
  if (!emailNormalized) throw new AuthError("邮箱不能为空", 400, { code: "EMAIL_REQUIRED" });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailNormalized)) {
    throw new AuthError("邮箱格式不正确", 400, { code: "EMAIL_INVALID" });
  }

  let username = (input.username || input.name || "").trim();
  if (!username) {
    username = emailNormalized.split("@")[0] || "user";
  }
  const password = input.password || "";
  if (!username) throw new AuthError("用户名不能为空");
  const passwordError = validatePasswordAgainstPolicy(password, DEFAULT_PASSWORD_POLICY);
  if (passwordError) throw new AuthError(passwordError);

  // Non-production test suites can auto-verify + create session to avoid rewriting
  // every fixture. Dedicated verification tests must unset FANJIN_TEST_AUTO_VERIFY_EMAIL.
  const testAutoVerify =
    process.env.NODE_ENV !== "prod" && process.env.FANJIN_TEST_AUTO_VERIFY_EMAIL === "1";

  if (!testAutoVerify) {
    if (!(await isMailConfigured())) {
      throw new AuthError("邮件服务未配置，请联系管理员", 503, { code: "MAIL_NOT_CONFIGURED" });
    }
    if (!resolvePasswordResetPublicBaseUrl()) {
      throw new AuthError("邮件服务未配置，请联系管理员", 503, { code: "MAIL_NOT_CONFIGURED" });
    }
  }

  // Resolve username collisions for auto-derived local-parts
  let finalUsername = username;
  if (!input.username && !input.name) {
    let suffix = 0;
    while (await knex<any>("o_user").where("name", finalUsername).first()) {
      suffix += 1;
      finalUsername = `${username}${suffix}`;
    }
  }

  const exists = await knex<any>("o_user")
    .where("name", finalUsername)
    .orWhereRaw("lower(email) = ?", [emailNormalized])
    .first();
  if (exists) throw new AuthError("账号已存在", 409, { code: "USER_EXISTS" });

  const timestamp = now();
  // Public registration never mints platform authority. The root account is
  // created only by the explicit startup bootstrap guarded by
  // FANJIN_ROOT_PASSWORD.
  const role = "owner";
  const workspaceId = uuid();
  const workspaceName = (input.workspaceName || `${finalUsername}'s Workspace`).trim();
  const workspaceSlug = await uniqueWorkspaceSlug(knex, workspaceName || finalUsername);
  let userId = 0;

  await knex.transaction(async (trx) => {
    userId = await insertAndReturnId(trx, "o_user", {
      name: finalUsername,
      email: emailNormalized,
      displayName: finalUsername,
      password: await hashPassword(password),
      passwordChangedAt: timestamp,
      role,
      status: "active",
      emailVerifiedAt: testAutoVerify ? timestamp : null,
      currentWorkspaceId: workspaceId,
      defaultWorkspaceId: workspaceId,
      createdAt: timestamp,
      updatedAt: timestamp,
      lastLoginAt: null,
    });
    if (!userId) throw new AuthError("用户创建失败", 500);
    await trx<any>("o_workspace").insert({
      id: workspaceId,
      name: workspaceName || DEFAULT_WORKSPACE_NAME,
      slug: workspaceSlug,
      ownerUserId: userId,
      status: "active",
      createdAt: timestamp,
      updatedAt: timestamp,
    });
    await trx<any>("o_workspace_member").insert({
      id: uuid(),
      workspaceId,
      userId,
      role: "owner",
      status: "active",
      createdAt: timestamp,
      updatedAt: timestamp,
    });
    await ensureWorkspaceBillingAccountRecord(trx, { workspaceId, timestamp });
    // 0.1.4 注册租户归属：从注册入口 Host 解析的商业租户写入不可变归属。
    // 登录入口 Host 永远不修改这些字段；ownerTenantId 只能由平台管理员修改。
    if (input.registrationTenant?.tenantId) {
      await ensureUserAttributionInTransaction(trx, userId, {
        registeredTenantId: input.registrationTenant.tenantId,
        registrationHostname: input.registrationTenant.hostname ?? null,
        registrationSource: input.registrationTenant.source || "public_signup",
      });
    }
  });

  if (testAutoVerify) {
    const user = await knex<any>("o_user").where("id", userId).first();
    return await createSession(knex, user, authInfo);
  }

  try {
    const issued = await issueEmailVerification(knex, {
      id: userId,
      email: emailNormalized,
      name: finalUsername,
      handoffSeed: authInfo.handoffSeed,
    });
    await sendEmailVerificationMail({
      email: emailNormalized,
      verifyUrl: issued.verifyUrl,
      code: issued.code,
    });
  } catch (err: any) {
    console.error("[auth] verification email delivery failed", err?.message || err);
    await deleteUnverifiedRegistration(knex, userId);
    throw new AuthError("验证邮件发送失败，请稍后重试", 502, { code: "MAIL_DELIVERY_FAILED" });
  }

  return {
    email: emailNormalized,
    delivery: "email",
    requiresVerification: true,
  };
}

export async function revokeSession(knex: Knex, rawToken: string, sessionId?: string): Promise<void> {
  const timestamp = now();
  const query = knex<any>("o_user_session").whereNull("revokedAt");
  if (sessionId) {
    query.andWhere("id", sessionId);
  } else if (rawToken) {
    query.andWhere("tokenHash", hashAuthToken(rawToken));
  } else {
    return;
  }
  await query.update({ revokedAt: timestamp, updatedAt: timestamp });
}
