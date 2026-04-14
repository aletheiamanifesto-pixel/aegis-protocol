"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { AlertTriangle, CheckCircle2, Recycle, ShieldCheck } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { getDPP, verifyProduct, type DPPDetailResponse, type VerifyResponse } from "@/lib/api";

const countryFlags: Record<string, string> = {
  italy: "🇮🇹",
  france: "🇫🇷",
  germany: "🇩🇪",
  spain: "🇪🇸",
  portugal: "🇵🇹",
  netherlands: "🇳🇱"
};

function LoadingSkeleton() {
  return (
    <main className="mx-auto w-full max-w-md space-y-4 p-4">
      {[1, 2, 3, 4].map((i) => (
        <div key={i} className="h-20 animate-pulse rounded-lg bg-slate-100" />
      ))}
    </main>
  );
}

export default function VerifyPage({ params }: { params: { productId: string } }) {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [verify, setVerify] = useState<VerifyResponse | null>(null);
  const [fullDpp, setFullDpp] = useState<DPPDetailResponse | null>(null);

  useEffect(() => {
    async function run() {
      try {
        const verifyData = await verifyProduct(params.productId);
        setVerify(verifyData);
        if (verifyData?.passport_data?.dpp_id) {
          try {
            const full = await getDPP(verifyData.passport_data.dpp_id);
            setFullDpp(full);
          } catch {
            setFullDpp(null);
          }
        }
      } catch (e) {
        setError(e instanceof Error ? e.message : "Unable to verify this product right now.");
      } finally {
        setLoading(false);
      }
    }
    run();
  }, [params.productId]);

  if (loading) return <LoadingSkeleton />;

  if (error) {
    return (
      <main className="mx-auto max-w-md p-4">
        <Card className="border-red-200">
          <CardContent className="p-6 text-center">
            <AlertTriangle className="mx-auto mb-3 h-8 w-8 text-red-600" />
            <h1 className="text-xl font-semibold">We couldn&apos;t reach HALA verification right now</h1>
            <p className="mt-2 text-sm text-slate-600">Please try again in a moment. If this continues, contact the brand directly.</p>
          </CardContent>
        </Card>
      </main>
    );
  }

  if (!verify?.passport_data) {
    return (
      <main className="mx-auto max-w-md p-4">
        <Card>
          <CardContent className="p-6 text-center">
            <h1 className="text-xl font-semibold">Product not found</h1>
            <p className="mt-2 text-sm text-slate-600">This product ID does not exist in the HALA registry.</p>
          </CardContent>
        </Card>
      </main>
    );
  }

  const data = { ...verify.passport_data, ...(fullDpp || {}) };
  const revoked = fullDpp?.is_active === false || verify.is_valid === false;
  const origin = data.origin_country || "Unknown";
  const key = origin.toLowerCase();
  const carbon = Number(data.carbon_footprint_kg || 0);

  return (
    <main className="mx-auto w-full max-w-md space-y-4 p-4 pb-10">
      <header className="flex items-center gap-2 text-sm font-semibold">
        <ShieldCheck className="h-4 w-4 text-green-600" /> HALA
      </header>

      <Card className={revoked ? "border-red-300 bg-red-50" : "border-green-300 bg-green-50"}>
        <CardHeader className="pb-2"><CardTitle className="text-base">{revoked ? "❌ PASSPORT REVOKED" : "✅ VERIFIED PRODUCT"}</CardTitle></CardHeader>
        <CardContent className="text-sm">
          {revoked ? "This passport has been revoked." : "Authenticity confirmed on Polygon blockchain."}
          <p className="mt-1 text-xs text-slate-600">Version: {data.version || 1}</p>
        </CardContent>
      </Card>

      <section>
        <h1 className="text-2xl font-bold">{data.product_name}</h1>
        <p className="text-slate-600">by {data.brand_name || "Unknown brand"}</p>
      </section>

      <Separator />
      <section className="space-y-2">
        <h2 className="text-xs font-semibold tracking-wider text-slate-500">ORIGIN</h2>
        <p>📍 {countryFlags[key] || "🌍"} {origin}</p>
      </section>

      <Separator />
      <section className="space-y-2">
        <h2 className="text-xs font-semibold tracking-wider text-slate-500">MATERIALS</h2>
        <div className="flex flex-wrap gap-2">{(data.materials || []).map((material) => <Badge key={material} variant="secondary">{material}</Badge>)}</div>
      </section>

      <Separator />
      <section className="space-y-2">
        <h2 className="text-xs font-semibold tracking-wider text-slate-500">CERTIFICATIONS</h2>
        {(data.certifications || []).length ? (data.certifications || []).map((cert) => <p key={cert} className="text-sm">✅ {cert}</p>) : <p className="text-sm text-slate-500">No certifications declared</p>}
      </section>

      <Separator />
      <section className="space-y-2">
        <h2 className="text-xs font-semibold tracking-wider text-slate-500">SUSTAINABILITY</h2>
        <p className="text-sm">Carbon: {carbon.toFixed(1)} kg CO₂</p>
        <div className="h-2 rounded-full bg-slate-100"><div className={`h-2 rounded-full ${carbon > 10 ? "bg-red-500" : carbon > 4 ? "bg-amber-500" : "bg-green-600"}`} style={{ width: `${Math.min(100, (carbon / 10) * 100)}%` }} /></div>
        <p className="text-sm">Recyclability: {data.recyclability_percent ?? "N/A"}%</p>
      </section>

      <Separator />
      <section className="space-y-2">
        <h2 className="text-xs font-semibold tracking-wider text-slate-500">HOW TO RECYCLE</h2>
        <p className="text-sm"><Recycle className="mr-1 inline h-4 w-4" />{data.recycling_instructions || "Follow local sorting instructions."}</p>
      </section>

      <Separator />
      <section className="space-y-1 text-sm">
        <h2 className="text-xs font-semibold tracking-wider text-slate-500">BLOCKCHAIN PROOF</h2>
        <p>Hash: {data.dpp_hash || "N/A"}</p>
        <p>Version: {data.version || 1}</p>
        <p>IPFS: {data.ipfs_cid ? <a className="text-green-700 underline" href={`https://ipfs.io/ipfs/${data.ipfs_cid}`} target="_blank" rel="noreferrer">{data.ipfs_cid}</a> : "N/A"}</p>
      </section>

      <Separator />
      <footer className="text-center text-sm text-slate-600">
        Powered by HALA.wtf
        <div><Link href="/register" className="text-green-700 underline">Your brand needs HALA? →</Link></div>
      </footer>
    </main>
  );
}
