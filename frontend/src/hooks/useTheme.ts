"use client";

import { useCallback, useEffect, useRef } from "react";
import { useAppStore } from "./useAppStore";

export function useTheme() {
  const { state, dispatch } = useAppStore();
  const initializedRef = useRef(false);

  useEffect(() => {
    if (initializedRef.current) {
      return;
    }
    initializedRef.current = true;

    const saved = localStorage.getItem("theme");
    const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
    dispatch({ type: "SET_DARK", value: saved === "dark" || (!saved && prefersDark) });
  }, [dispatch]);

  useEffect(() => {
    document.documentElement.classList.toggle("dark", state.isDark);
    document.body.classList.toggle("dark", state.isDark);
    localStorage.setItem("theme", state.isDark ? "dark" : "light");
  }, [state.isDark]);

  const toggleDark = useCallback(() => {
    dispatch({ type: "TOGGLE_DARK" });
  }, [dispatch]);

  return { isDark: state.isDark, toggleDark };
}
