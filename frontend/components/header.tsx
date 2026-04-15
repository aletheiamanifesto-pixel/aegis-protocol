import Link from "next/link";

import { Button } from "@/components/ui/button";

export function Header() {
  return (
    <header className="border-b border-slate-200 bg-white/90 backdrop-blur">
      <div className="mx-auto flex h-16 max-w-6xl items-center justify-between px-4">
        <Link className="text-xl font-bold text-emerald-700" href="/">
          HALA.wtf
        </Link>
        <nav className="hidden items-center gap-6 text-sm text-slate-600 md:flex">
          <Link href="/pricing">Pricing</Link>
          <Link href="#">Blog</Link>
          <Link href="#">Docs</Link>
          <Link href="#">Contact</Link>
        </nav>
        <div className="flex gap-2">
          <Link href="/login">
            <Button variant="ghost">Login</Button>
          </Link>
          <Link href="/register">
            <Button>Inizia Gratis</Button>
          </Link>
        </div>
      </div>
    </header>
  );
}
