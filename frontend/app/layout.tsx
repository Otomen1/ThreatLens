import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import "./globals.css";

import { SystemStatus } from "@/components/SystemStatus";

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-inter",
});

const jetbrainsMono = JetBrains_Mono({
  subsets: ["latin"],
  variable: "--font-mono",
});

export const metadata: Metadata = {
  title: "ThreatLens",
  description:
    "AI-powered Threat Intelligence & Detection Engineering Platform. Search any indicator, technique, actor, or vulnerability.",
  openGraph: {
    title: "ThreatLens",
    description: "Search anything in threat intelligence, understand it instantly.",
    type: "website",
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className={`${inter.variable} ${jetbrainsMono.variable} font-sans bg-zinc-950 text-white antialiased`}>
        <SystemStatus />
        {children}
      </body>
    </html>
  );
}
