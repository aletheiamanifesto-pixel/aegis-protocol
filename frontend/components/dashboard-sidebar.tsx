"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

const items = [
  { href: "/dashboard", label: "Dashboard" },
  { href: "/dashboard/products/new", label: "Prodotti" },
  { href: "/dashboard/dpp/new", label: "Crea DPP" },
  { href: "/dashboard/settings", label: "Settings" }
];

export function DashboardSidebar() {
  const pathname = usePathname();

  return (
    <aside className="w-full border-b border-slate-200 bg-white p-4 lg:h-screen lg:w-64 lg:border-b-0 lg:border-r">
      <div className="mb-6 text-xl font-bold text-emerald-700">HALA</div>
      <nav className="flex flex-wrap gap-2 lg:flex-col">
        {items.map((item) => (
          <Link
            className={cn(
              "rounded-md px-3 py-2 text-sm",
              pathname === item.href ? "bg-emerald-100 text-emerald-800" : "text-slate-600 hover:bg-slate-100"
            )}
            href={item.href}
            key={item.href}
          >
            {item.label}
          </Link>
        ))}
      </nav>
      <div className="mt-6 lg:mt-auto lg:pt-8">
        <Badge variant="secondary">Piano attivo</Badge>
      </div>
    </aside>
  );
}
