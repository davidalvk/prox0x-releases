import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import type { ModuleId, RouteFilter } from "../types";

interface AppContextValue {
  activeModule: ModuleId;
  setActiveModule: (module: ModuleId) => void;
  selectedFlowId: number | null;
  setSelectedFlowId: (flowId: number | null) => void;
  sendToRepeater: (flowId: number, rawRequest?: string) => void;
  repeaterRawRequest: string | null;
  sendToIntruder: (flowId: number) => void;
  proxyRouteFilter: RouteFilter | null;
  setProxyRouteFilter: (filter: RouteFilter | null) => void;
  currentProject: string | null;
  setCurrentProject: (project: string | null) => void;
  scopeRevision: number;
  notifyScopeChanged: () => void;
  pendingFullScan: boolean;
  requestFullScan: () => void;
  consumeFullScanRequest: () => void;
}

const AppContext = createContext<AppContextValue | null>(null);

export function AppProvider({ children }: { children: ReactNode }) {
  const [activeModule, setActiveModule] = useState<ModuleId>("proxy");
  const [selectedFlowId, setSelectedFlowId] = useState<number | null>(null);
  const [repeaterRawRequest, setRepeaterRawRequest] = useState<string | null>(
    null,
  );
  const [proxyRouteFilter, setProxyRouteFilter] = useState<RouteFilter | null>(null);
  const [currentProject, setCurrentProjectState] = useState<string | null>(null);
  const [scopeRevision, setScopeRevision] = useState(0);
  const [pendingFullScan, setPendingFullScan] = useState(false);

  const notifyScopeChanged = useCallback(() => {
    setScopeRevision((value) => value + 1);
  }, []);

  const requestFullScan = useCallback(() => {
    setPendingFullScan(true);
    setActiveModule("active-scan");
  }, []);

  const consumeFullScanRequest = useCallback(() => {
    setPendingFullScan(false);
  }, []);

  const setCurrentProject = useCallback((project: string | null) => {
    setCurrentProjectState(project);
    setSelectedFlowId(null);
    setRepeaterRawRequest(null);
    setProxyRouteFilter(null);
    setPendingFullScan(false);
    setActiveModule("proxy");
  }, []);

  const sendToRepeater = useCallback(
    (flowId: number, rawRequest?: string) => {
      setSelectedFlowId(flowId);
      setRepeaterRawRequest(rawRequest ?? null);
      setActiveModule("repeater");
    },
    [],
  );

  const sendToIntruder = useCallback((flowId: number) => {
    setSelectedFlowId(flowId);
    setActiveModule("intruder");
  }, []);

  const value = useMemo(
    () => ({
      activeModule,
      setActiveModule,
      selectedFlowId,
      setSelectedFlowId,
      sendToRepeater,
      repeaterRawRequest,
      sendToIntruder,
      proxyRouteFilter,
      setProxyRouteFilter,
      currentProject,
      setCurrentProject,
      scopeRevision,
      notifyScopeChanged,
      pendingFullScan,
      requestFullScan,
      consumeFullScanRequest,
    }),
    [
      activeModule,
      selectedFlowId,
      sendToRepeater,
      repeaterRawRequest,
      sendToIntruder,
      proxyRouteFilter,
      currentProject,
      setCurrentProject,
      scopeRevision,
      notifyScopeChanged,
      pendingFullScan,
      requestFullScan,
      consumeFullScanRequest,
    ],
  );

  return <AppContext.Provider value={value}>{children}</AppContext.Provider>;
}

export function useApp(): AppContextValue {
  const context = useContext(AppContext);
  if (!context) {
    throw new Error("useApp debe usarse dentro de AppProvider");
  }
  return context;
}
