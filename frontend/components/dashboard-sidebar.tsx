"use client";

import Link from "next/link";
import Image from "next/image";
import { usePathname, useRouter } from "next/navigation";
import { Home, Package, ScrollText, Settings, LogOut } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { clearAuth, useAuth } from "@/lib/auth";
import { cn } from "@/lib/utils";

const items = [
  { href: "/dashboard", label: "Dashboard", icon: Home },
  { href: "/dashboard/products/new", label: "Products", icon: Package },
  { href: "/dashboard/dpp/new", label: "Create DPP", icon: ScrollText },
  { href: "/dashboard/settings", label: "Settings", icon: Settings }
];

export function DashboardSidebar() {
  const pathname = usePathname();
  const { auth } = useAuth();
  const router = useRouter();

  return (
    <aside className="w-full border-b bg-white p-4 md:w-64 md:border-b-0 md:border-r md:min-h-screen">
      <Link href="/dashboard" className="mb-6 flex items-center gap-2 text-lg font-semibold">
        <Image src="/hala-logo.svg" alt="HALA logo" width={120} height={36} className="h-8 w-auto" />
      </Link>
      <nav className="space-y-2">
        {items.map((item) => {
          const Icon = item.icon;
          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "flex items-center gap-2 rounded-md px-3 py-2 text-sm hover:bg-muted",
                pathname === item.href ? "bg-muted font-medium" : "text-slate-600"
              )}
            >
              <Icon className="h-4 w-4" />
              {item.label}
            </Link>
          );
        })}
      </nav>
      <div className="mt-6 space-y-3">
        <Badge variant="secondary">Plan: {(auth?.plan || "free").toUpperCase()}</Badge>
        <Button
          variant="outline"
          className="w-full justify-start"
          onClick={() => {
            clearAuth();
            router.replace("/login");
          }}
        >
          <LogOut className="mr-2 h-4 w-4" /> Logout
        </Button>
      </div>
    </aside>
  );
}
