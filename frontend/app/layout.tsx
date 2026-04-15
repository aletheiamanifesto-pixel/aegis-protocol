import type { Metadata } from "next";

import "./globals.css";
import { Providers } from "./providers";

export const metadata: Metadata = {
  title: "HALA.wtf",
  description: "Digital Product Passport in 5 minuti"
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="it">
      <body className="font-sans">
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
