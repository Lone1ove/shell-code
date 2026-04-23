import type { Metadata } from "next";
import "./globals.css";
import { ThemeInitializer } from "@/components/ThemeInitializer";

export const metadata: Metadata = {
  title: "Shell-Agent",
  description: "AI 驱动的自动化渗透测试工作流",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="zh-CN" suppressHydrationWarning>
      <body className="min-h-screen flex flex-col">
        <ThemeInitializer />
        {children}
      </body>
    </html>
  );
}
