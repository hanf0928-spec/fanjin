import { Suspense, useEffect } from "react";
import { RouterProvider } from "react-router-dom";
import { router } from "./routes";
import { useV4Theme } from "./ui/useV4Theme";
import { StepUpProvider } from "./components/StepUpProvider";
import { ToastProvider } from "./ui/console/feedback";
import FeedbackWidget from "./features/feedback/FeedbackWidget";
import { useAuthStore } from "./stores/authStore";

export default function App() {
  const theme = useV4Theme();
  const token = useAuthStore((s) => s.token);
  const autoLogin = useAuthStore((s) => s.autoLogin);

  // 应用启动时统一尝试一次自动登录，覆盖所有入口（包括完全不经过
  // RouteGuard 的公开首页，如 /workbench/create）。部署方未开启
  // FANJIN_ENABLE_AUTO_LOGIN 时后端 404，这里静默忽略，不影响正常登录流程。
  useEffect(() => {
    if (!token) void autoLogin();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <Suspense
      fallback={
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            height: "100vh",
            background: theme.bg,
            color: theme.textSecondary,
            fontSize: 15,
          }}
        >
          加载中…
        </div>
      }
    >
      <ToastProvider>
        <StepUpProvider>
          <RouterProvider router={router} />
          <FeedbackWidget />
        </StepUpProvider>
      </ToastProvider>
    </Suspense>
  );
}
