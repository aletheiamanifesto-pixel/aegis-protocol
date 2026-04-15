"use client";

import { ReactNode, useEffect, useState } from "react";

import { DashboardSidebar } from "@/components/dashboard-sidebar";

export default function DashboardLayout({ children }: { children: ReactNode }) {
  const [brandName, setBrandName] = useState("Brand");

  useEffect(() => {
    const name = localStorage.getItem("hala_brand_name");
    if (name) {
      setBrandName(name);
    }
  }, []);

  return (
    <div className="lg:flex">
      <DashboardSidebar />
      <div className="flex-1">
        <header className="border-b border-slate-200 bg-white px-4 py-3 text-sm text-slate-600">{brandName}</header>
        <main className="p-4">{children}</main>
      </div>
    </div>
  );
}
