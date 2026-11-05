import { createContext, useContext, type ReactNode } from "react";
import {
  useInterceptSocket,
  type InterceptSocketState,
} from "../hooks/useInterceptSocket";

const InterceptContext = createContext<InterceptSocketState | null>(null);

export function InterceptProvider({ children }: { children: ReactNode }) {
  const state = useInterceptSocket();
  return (
    <InterceptContext.Provider value={state}>
      {children}
    </InterceptContext.Provider>
  );
}

export function useIntercept(): InterceptSocketState {
  const context = useContext(InterceptContext);
  if (!context) {
    throw new Error("useIntercept debe usarse dentro de InterceptProvider");
  }
  return context;
}
