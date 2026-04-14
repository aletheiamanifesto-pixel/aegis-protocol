"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { getBrandProducts, getBrandStats, verifyProduct, type ProductResponse, type StatsResponse } from "@/lib/api";
import { useAuth } from "@/lib/auth";

type ProductView = ProductResponse & { dppStatus: "Live" | "No DPP"; version: number; dppId?: number };

export default function DashboardHomePage() {
  const { auth } = useAuth();
  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [products, setProducts] = useState<ProductView[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function run() {
      if (!auth) return;
      setLoading(true);
      try {
        const [s, list] = await Promise.all([
          getBrandStats(auth.brandId, auth.apiKey),
          getBrandProducts(auth.brandId, auth.apiKey)
        ]);
        const enriched = await Promise.all(
          list.map(async (p) => {
            try {
              const verify = await verifyProduct(p.product_id);
              if (verify?.passport_data?.dpp_id && verify.is_valid) {
                return { ...p, dppStatus: "Live" as const, version: verify.passport_data.version || 1, dppId: verify.passport_data.dpp_id };
              }
            } catch {
              // ignore
            }
            return { ...p, dppStatus: "No DPP" as const, version: 0 };
          })
        );
        setStats(s);
        setProducts(enriched);
      } finally {
        setLoading(false);
      }
    }
    run();
  }, [auth]);

  if (loading) {
    return <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">{[1,2,3,4].map((i) => <div key={i} className="h-28 animate-pulse rounded-lg bg-white" />)}</div>;
  }

  const cards = [
    { label: "Total Products", value: stats?.total_products ?? 0 },
    { label: "Total Scans", value: stats?.total_scans ?? 0 },
    { label: "Compliance Score", value: `${stats?.compliance_percent ?? 0}%` },
    { label: "Current Plan", value: (auth?.plan || "free").toUpperCase() }
  ];

  return (
    <div className="space-y-6">
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {cards.map((card) => (
          <Card key={card.label}>
            <CardHeader className="pb-2"><CardTitle className="text-sm text-slate-500">{card.label}</CardTitle></CardHeader>
            <CardContent className="text-2xl font-bold">{card.value}</CardContent>
          </Card>
        ))}
      </div>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle>Products</CardTitle>
          <Button asChild><Link href="/dashboard/products/new">+ Add Product</Link></Button>
        </CardHeader>
        <CardContent className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-slate-500">
                <th className="p-2">Product Name</th><th className="p-2">SKU</th><th className="p-2">Category</th><th className="p-2">DPP Status</th><th className="p-2">Version</th><th className="p-2">Actions</th>
              </tr>
            </thead>
            <tbody>
              {products.map((p) => (
                <tr key={p.id} className="border-t">
                  <td className="p-2">{p.product_name}</td>
                  <td className="p-2">{p.product_id}</td>
                  <td className="p-2">{p.category}</td>
                  <td className="p-2">{p.dppStatus === "Live" ? <Badge>Live</Badge> : <Link href={`/dashboard/dpp/new?productId=${encodeURIComponent(p.product_id)}`} className="text-green-700 underline">No DPP</Link>}</td>
                  <td className="p-2">{p.version || "-"}</td>
                  <td className="p-2">{p.dppId ? <Link href={`/dashboard/dpp/${p.dppId}`} className="text-green-700 underline">Open</Link> : "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </CardContent>
      </Card>
    </div>
  );
}
