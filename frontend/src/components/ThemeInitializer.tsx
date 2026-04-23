"use client";

import { useEffect } from "react";

export function ThemeInitializer() {
  useEffect(() => {
    const saved = localStorage.getItem("theme");
    const prefersDark = window.matchMedia(
      "(prefers-color-scheme: dark)"
    ).matches;
    if (saved === "dark" || (!saved && prefersDark)) {
      document.body.classList.add("dark");
    } else {
      document.body.classList.remove("dark");
    }
  }, []);

  return null;
}
