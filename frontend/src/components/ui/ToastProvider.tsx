"use client";

import { useEffect, useRef, ReactNode } from "react";
import { useAppStore } from "@/hooks/useAppStore";
import { Toast } from "./Toast";
import { ToastType } from "@/types";

interface ToastProviderProps {
  children: ReactNode;
}

const TOAST_DISMISS_MS = 3500;
let toastId = 0;

export function ToastProvider({ children }: ToastProviderProps) {
  const { state, dispatch } = useAppStore();

  // 全局 showToast 函数
  useEffect(() => {
    (window as any).showToast = (message: string, type: ToastType = "info") => {
      const id = ++toastId;
      dispatch({ type: "ADD_TOAST", toast: { id, message, type } });
      setTimeout(() => {
        dispatch({ type: "REMOVE_TOAST", id });
      }, TOAST_DISMISS_MS);
    };
    return () => {
      delete (window as any).showToast;
    };
  }, [dispatch]);

  const handleDismiss = (id: number) => {
    dispatch({ type: "REMOVE_TOAST", id });
  };

  return (
    <>
      {children}
      {/* Toast 堆叠 */}
      <div className="fixed bottom-6 right-6 z-50 flex flex-col gap-2">
        {state.toasts.map((toast) => (
          <Toast key={toast.id} toast={toast} onDismiss={handleDismiss} />
        ))}
      </div>
    </>
  );
}

// 便利 hook
export function useToast() {
  return {
    showToast: (message: string, type: ToastType = "info") => {
      if (typeof window !== "undefined" && (window as any).showToast) {
        (window as any).showToast(message, type);
      }
    },
  };
}
