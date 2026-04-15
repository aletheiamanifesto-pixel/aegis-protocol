"use client";

import Link from "next/link";
import { Copy, Eye, EyeOff } from "lucide-react";
import { useMemo, useState } from "react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export default function SettingsPage() {
  const [show, setShow] = useState(false);
  const apiKey = typeof window !== "undefined" ? localStorage.getItem("hala_api_key") || "" : "";
  const plan = typeof window !== "undefined" ? localStorage.getItem("hala_plan") || "free" : "free";
  const products = Number(typeof window !== "undefined" ? localStorage.getItem("hala_products_count") || 0 : 0);

  const usage = useMemo(() => {
    const limit = plan === "pro" ? 500 : 5;
    return { limit, value: Math.min(100, Math.round((products / limit) * 100)) };
  }, [plan, products]);

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader><CardTitle>Brand profile</CardTitle></CardHeader>
        <CardContent className="text-sm text-slate-600">
          <p><strong>Nome:</strong> {typeof window !== "undefined" ? localStorage.getItem("hala_brand_name") || "-" : "-"}</p>
          <p><strong>Email:</strong> {typeof window !== "undefined" ? localStorage.getItem("hala_brand_email") || "-" : "-"}</p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle>API Key</CardTitle></CardHeader>
        <CardContent>
          <div className="flex items-center gap-2">
            <code className="flex-1 rounded bg-slate-100 p-2 text-xs">{show ? apiKey : "•".repeat(Math.max(apiKey.length, 12))}</code>
            <Button onClick={() => setShow((v) => !v)} size="sm" variant="outline">{show ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}</Button>
            <Button onClick={() => navigator.clipboard.writeText(apiKey)} size="sm" variant="outline"><Copy className="h-4 w-4" /></Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle>Piano</CardTitle></CardHeader>
        <CardContent className="space-y-2">
          <p className="text-sm">{products}/{usage.limit} prodotti</p>
          <div className="h-2 w-full rounded bg-slate-100"><div className="h-2 rounded bg-emerald-500" style={{ width: `${usage.value}%` }} /></div>
          <Link href="/pricing"><Button>⬆️ Upgrade a PRO — €49/mese</Button></Link>
        </CardContent>
      </Card>
    </div>
  );
}
