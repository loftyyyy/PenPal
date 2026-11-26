import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { useQueryClient } from "@tanstack/react-query";
import { api, onUnauthorized, setAccessToken } from "../lib/api";
import type { LoginRequest, UserSummary } from "../lib/types";

const TOKEN_KEY = "penpal.token";
const EXPIRES_KEY = "penpal.expiresAt";

interface AuthContextValue {
  user: UserSummary | null;
  initializing: boolean;
  login: (credentials: LoginRequest) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

function storedToken(): string | null {
  const token = sessionStorage.getItem(TOKEN_KEY);
  const expiresAt = Number(sessionStorage.getItem(EXPIRES_KEY));
  if (!token) return null;
  if (Number.isFinite(expiresAt) && expiresAt <= Date.now()) {
    sessionStorage.removeItem(TOKEN_KEY);
    sessionStorage.removeItem(EXPIRES_KEY);
    return null;
  }
  return token;
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();
  const [user, setUser] = useState<UserSummary | null>(null);
  const [initializing, setInitializing] = useState(() => storedToken() !== null);

  const clearSession = useCallback(() => {
    setAccessToken(null);
    sessionStorage.removeItem(TOKEN_KEY);
    sessionStorage.removeItem(EXPIRES_KEY);
    setUser(null);
    queryClient.clear();
  }, [queryClient]);

  const logout = useCallback(() => {
    clearSession();
  }, [clearSession]);

  useEffect(() => {
    onUnauthorized(() => clearSession());
    return () => onUnauthorized(null);
  }, [clearSession]);

  useEffect(() => {
    const token = storedToken();
    if (!token) {
      setInitializing(false);
      return;
    }
    setAccessToken(token);
    let active = true;
    api.auth
      .me()
      .then((me) => {
        if (active) setUser(me);
      })
      .catch(() => {
        if (active) clearSession();
      })
      .finally(() => {
        if (active) setInitializing(false);
      });
    return () => {
      active = false;
    };
  }, [clearSession]);

  const login = useCallback(
    async (credentials: LoginRequest) => {
      const response = await api.auth.login(credentials);
      // sessionStorage keeps the token per tab and clears when the tab closes.
      // There is no refresh endpoint, so expiry forces a new login.
      sessionStorage.setItem(TOKEN_KEY, response.access_token);
      sessionStorage.setItem(
        EXPIRES_KEY,
        String(Date.now() + response.expires_in * 1000),
      );
      setAccessToken(response.access_token);
      setUser(response.user);
    },
    [],
  );

  const value = useMemo(
    () => ({ user, initializing, login, logout }),
    [user, initializing, login, logout],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth must be used inside AuthProvider");
  return context;
}
