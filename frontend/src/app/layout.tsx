import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "S-Gates | Application Security Gateway",
  description:
    "Pre-release source code scanner and approval gate for GitHub repositories and ZIP archives.",
  icons: {
    icon: "/favicon.svg",
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen bg-[#070b14] text-slate-100 antialiased selection:bg-emerald-500/30 selection:text-emerald-200">
        {children}
      </body>
    </html>
  );
}

