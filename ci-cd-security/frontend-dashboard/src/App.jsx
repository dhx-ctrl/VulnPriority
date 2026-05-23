import React, { useEffect } from "react";
import { useAuth, useRouter } from "./context/AppContext.jsx";
import { useData } from "./context/DataContext.jsx";
import { AppLayout } from "./components/Layout.jsx";
import LoginPage from "./pages/LoginPage.jsx";
import RegisterPage from "./pages/RegisterPage.jsx";
import PendingAccessPage from "./pages/PendingAccessPage.jsx";
import DashboardPage from "./pages/DashboardPage.jsx";
import FindingsPage from "./pages/FindingsPage.jsx";
import ScanHistoryPage from "./pages/ScanHistoryPage.jsx";
import ModelInsightsPage from "./pages/ModelInsightsPage.jsx";
import ParametersPage from "./pages/ParametersPage.jsx";
import SyncPage from "./pages/SyncPage.jsx";
import SummaryPage from "./pages/SummaryPage.jsx";
import UsersPage from "./pages/UsersPage.jsx";
export default function App() {
  const { path, navigate } = useRouter();
  const { user } = useAuth();
  const { loadingData, dataLoaded, loadData, clearData } = useData();
  const publicPaths = ["/login", "/register", "/pending-access"];
  useEffect(() => {
    if (!user) {
      clearData();
      return;
    }
    if (!publicPaths.includes(path)) {
      loadData();
    }
  }, [user, path, loadData, clearData]);
  if (!user && !publicPaths.includes(path)) {
    navigate("/login");
    return null;
  }
  if (user && publicPaths.includes(path)) {
    navigate("/dashboard");
    return null;
  }
  if (path === "/login") return <LoginPage />;
  if (path === "/register") return <RegisterPage />;
  if (path === "/pending-access") return <PendingAccessPage />;
  if (path === "/users" && !user?.is_admin) {
    navigate("/dashboard");
    return null;
  }
  if (loadingData && !dataLoaded) {
    return (
      <AppLayout>
        <div
          style={{
            padding: 40,
            fontSize: 14,
            color: "#64748b",
            textAlign: "center",
          }}
        >
          Loading findings from FastAPI backend…
        </div>
      </AppLayout>
    );
  }
  const pages = {
    "/dashboard": DashboardPage,
    "/findings": FindingsPage,
    "/scans": ScanHistoryPage,
    "/model": ModelInsightsPage,
    "/parameters": ParametersPage,
    "/sync": SyncPage,
    "/summary": SummaryPage,
    "/users": UsersPage,
  };
  const Page = pages[path] || DashboardPage;
  return (
    <AppLayout>
      <Page />
    </AppLayout>
  );
}
