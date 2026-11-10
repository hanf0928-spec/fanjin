import express from "express";
import { db } from "@/utils/db";
import { AuthError, autoLoginAsPlatformRoot } from "@/lib/auth";
import { error, success } from "@/lib/responseFormat";

const router = express.Router();

// Operator opt-in only: without FANJIN_ENABLE_AUTO_LOGIN=1 this endpoint
// behaves as if it does not exist, so cloning/running this project never
// silently exposes a credential-free admin login.
function autoLoginEnabled(): boolean {
  return String(process.env.FANJIN_ENABLE_AUTO_LOGIN || "").trim() === "1";
}

router.post("/", async (req, res) => {
  if (!autoLoginEnabled()) {
    return res.status(404).send(error("接口不存在"));
  }
  try {
    const result = (await autoLoginAsPlatformRoot(db as any, {
      userAgent: Array.isArray(req.headers["user-agent"])
        ? req.headers["user-agent"].join(",")
        : req.headers["user-agent"],
      ip: req.ip,
    })) as any;
    const { rawToken, ...data } = result;
    return res.status(200).send(success(data, "已自动登录"));
  } catch (err: any) {
    const status = err instanceof AuthError ? err.status : 400;
    return res.status(status).send(error(
      err?.message || "自动登录失败",
      err instanceof AuthError ? { code: err.code } : null,
    ));
  }
});

export default router;
