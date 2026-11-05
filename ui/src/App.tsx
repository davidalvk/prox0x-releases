import { useApp } from "./context/AppContext";
import { InterceptProvider } from "./context/InterceptContext";
import { Layout } from "./components/Layout";
import { PageErrorBoundary } from "./components/ErrorBoundary";
import { WelcomeScreen } from "./components/WelcomeScreen";
import { HomeView } from "./pages/HomeView";
import { ProxyPage } from "./pages/ProxyPage";
import { RepeaterPage } from "./pages/RepeaterPage";
import { IntruderPage } from "./pages/IntruderPage";
import { FindingsView } from "./pages/FindingsView";
import { ActiveScanView } from "./pages/ActiveScanView";
import { ComparerView } from "./pages/ComparerView";
import { SessionSettingsView } from "./pages/SessionSettingsView";
import { OOBView } from "./pages/OOBView";
import { SitemapPage } from "./pages/SitemapPage";
import { DecoderPage } from "./pages/DecoderPage";
import { MatchReplacePage } from "./pages/MatchReplacePage";

export default function App() {
  const { activeModule, currentProject } = useApp();

  if (currentProject === null) {
    return <WelcomeScreen />;
  }

  return (
    <InterceptProvider key={currentProject}>
      <Layout>
        <PageErrorBoundary key={activeModule} pageName={activeModule}>
          {activeModule === "home" && <HomeView />}
          {activeModule === "proxy" && <ProxyPage />}
          {activeModule === "repeater" && <RepeaterPage />}
          {activeModule === "intruder" && <IntruderPage />}
          {activeModule === "findings" && <FindingsView />}
          {activeModule === "active-scan" && <ActiveScanView />}
          {activeModule === "comparer" && <ComparerView />}
          {activeModule === "settings" && <SessionSettingsView />}
          {activeModule === "oob" && <OOBView />}
          {activeModule === "sitemap" && <SitemapPage />}
          {activeModule === "decoder" && <DecoderPage />}
          {activeModule === "match-replace" && <MatchReplacePage />}
        </PageErrorBoundary>
      </Layout>
    </InterceptProvider>
  );
}
