"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";

import { DashboardSidebar } from "@/components/dashboard-sidebar";
import { useAuth } from "@/lib/auth";

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const { auth, ready } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (ready && !auth) router.replace("/login");
  }, [ready, auth, router]);

  if (!ready || !auth) {
    return <div className="p-8 text-sm text-slate-500">Loading dashboard...</div>;
  }

  return (
    <div className="md:flex">
      <DashboardSidebar />
      <main className="flex-1 bg-slate-50 p-4 md:p-6">{children}</main>
    </div>
  );
}
