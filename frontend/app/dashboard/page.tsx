"use client";

import Link from "next/link";
import { useQuery } from "@tanstack/react-query";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { getBrandStats, listBrandProducts, verifyProduct } from "@/lib/api";

function getBrandId() {
  const id = localStorage.getItem("hala_brand_id");
  return id ? Number(id) : 0;
}

export default function DashboardHomePage() {
  const brandId = typeof window !== "undefined" ? getBrandId() : 0;
  const plan = typeof window !== "undefined" ? localStorage.getItem("hala_plan") || "free" : "free";

  const statsQuery = useQuery({ queryKey: ["stats", brandId], queryFn: () => getBrandStats(brandId), enabled: !!brandId });
  const productsQuery = useQuery({ queryKey: ["products", brandId], queryFn: () => listBrandProducts(brandId), enabled: !!brandId });
  const statusQuery = useQuery({
    queryKey: ["product-status", productsQuery.data?.map((p) => p.product_id).join("|")],
    enabled: !!productsQuery.data,
    queryFn: async () => {
      const list = productsQuery.data || [];
      const checks = await Promise.all(list.map((p) => verifyProduct(p.product_id).catch(() => ({ is_valid: false, passport_data: null }))));
      return Object.fromEntries(list.map((p, i) => [p.product_id, checks[i]]));
    }
  });

  if (statsQuery.error || productsQuery.error) {
    return <p className="text-red-500">Errore caricamento dashboard</p>;
  }

  const stats = statsQuery.data;
  const products = productsQuery.data || [];

  return (
    <div className="space-y-4">
      <div className="grid gap-3 md:grid-cols-4">
        <Card><CardHeader><CardTitle>Prodotti totali</CardTitle></CardHeader><CardContent>{stats?.total_products ?? "-"}</CardContent></Card>
        <Card><CardHeader><CardTitle>Scansioni</CardTitle></CardHeader><CardContent>{stats?.total_scans ?? "-"}</CardContent></Card>
        <Card><CardHeader><CardTitle>Compliance %</CardTitle></CardHeader><CardContent className={(stats?.compliance_percent || 0) >= 80 ? "text-emerald-700" : "text-amber-600"}>{stats?.compliance_percent ?? "-"}%</CardContent></Card>
        <Card><CardHeader><CardTitle>Piano attuale</CardTitle></CardHeader><CardContent>{plan}</CardContent></Card>
      </div>

      <Card>
        <CardHeader className="flex-row items-center justify-between">
          <CardTitle>Prodotti</CardTitle>
          <Link href="/dashboard/products/new"><Button>+ Aggiungi Prodotto</Button></Link>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b text-left text-slate-500"><th className="py-2">Nome</th><th>SKU</th><th>Categoria</th><th>DPP Status</th><th>Azioni</th></tr>
              </thead>
              <tbody>
                {products.map((product) => {
                  const verification = statusQuery.data?.[product.product_id];
                  const dppId = Number((verification?.passport_data as { dpp_id?: number } | null)?.dpp_id || 0);
                  return (
                    <tr className="border-b" key={product.id}>
                      <td className="py-2">{product.product_name}</td>
                      <td>{product.product_id}</td>
                      <td>{product.category}</td>
                      <td>
                        {verification?.is_valid ? <Badge>✅ Live</Badge> : <Badge variant="secondary">⚠️ No DPP</Badge>}
                      </td>
                      <td>
                        {dppId ? <Link className="text-emerald-700" href={`/dashboard/dpp/${dppId}`}>Apri</Link> : <Link className="text-amber-600" href={`/dashboard/dpp/new?productId=${product.product_id}`}>Crea DPP</Link>}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
