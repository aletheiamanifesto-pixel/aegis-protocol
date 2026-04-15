import Link from "next/link";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

async function getVerification(productId: string) {
  try {
    const response = await fetch(`${API_BASE}/proofmint/verify/${encodeURIComponent(productId)}`, { cache: "no-store" });
    if (!response.ok) {
      return { is_valid: false, passport_data: null };
    }
    return (await response.json()) as { is_valid: boolean; passport_data: Record<string, unknown> | null };
  } catch {
    return { is_valid: false, passport_data: null };
  }
}

export default async function VerifyPage({ params }: { params: Promise<{ productId: string }> }) {
  const { productId } = await params;
  const verify = await getVerification(productId);
  const data = verify.passport_data || {};

  if (!verify.is_valid) {
    return (
      <main className="mx-auto min-h-screen max-w-md px-4 py-6">
        <Card className="border-red-200">
          <CardHeader>
            <Badge variant="destructive">❌ PRODOTTO NON VERIFICATO</Badge>
            <CardTitle className="text-xl">Questo prodotto non è registrato nel sistema HALA</CardTitle>
          </CardHeader>
          <CardContent>
            <Link className="text-sm text-emerald-700" href="#">Segnala questo prodotto</Link>
          </CardContent>
        </Card>
      </main>
    );
  }

  const cf = Number(data.carbon_footprint_kg || 0);
  const carbonWidth = Math.min(100, Math.max(0, cf * 10));

  return (
    <main className="mx-auto min-h-screen max-w-md space-y-3 px-4 py-5">
      <Card className="border-emerald-200">
        <CardHeader>
          <Badge>✅ PRODOTTO VERIFICATO</Badge>
          <p className="text-sm text-slate-600">Autenticità confermata su blockchain Polygon</p>
          <p className="text-xs text-slate-500">{new Date().toLocaleString("it-IT")}</p>
          <CardTitle>{String(data.product_name || "Prodotto")}</CardTitle>
          <p className="text-sm text-slate-600">Brand: {String(data.brand_name || "-")}</p>
        </CardHeader>
      </Card>

      <Card><CardHeader><CardTitle>📍 ORIGINE</CardTitle></CardHeader><CardContent>{String(data.origin_country || "-")}</CardContent></Card>
      <Card><CardHeader><CardTitle>🧪 COMPOSIZIONE</CardTitle></CardHeader><CardContent>{Array.isArray(data.materials) ? data.materials.join(", ") : "-"}</CardContent></Card>
      <Card>
        <CardHeader><CardTitle>📜 CERTIFICAZIONI</CardTitle></CardHeader>
        <CardContent className="space-y-1">
          {Array.isArray(data.certifications) && data.certifications.length > 0 ? data.certifications.map((cert) => <p key={String(cert)}>✅ {String(cert)}</p>) : <p>-</p>}
        </CardContent>
      </Card>
      <Card>
        <CardHeader><CardTitle>🌍 IMPATTO AMBIENTALE</CardTitle></CardHeader>
        <CardContent>
          <p>{cf} kg CO₂e</p>
          <div className="mt-2 h-2 w-full rounded bg-slate-100"><div className="h-2 rounded bg-emerald-500" style={{ width: `${carbonWidth}%` }} /></div>
        </CardContent>
      </Card>
      <Card><CardHeader><CardTitle>♻️ COME RICICLARE</CardTitle></CardHeader><CardContent>{String(data.recycling_instructions || "-")}</CardContent></Card>
      <Card>
        <CardHeader><CardTitle>🔗 VERIFICA BLOCKCHAIN</CardTitle></CardHeader>
        <CardContent>
          <p className="break-all text-xs text-slate-500">{String(data.dpp_hash || "-")}</p>
          <a className="text-sm text-emerald-700" href="#" target="_blank">Vedi su PolygonScan</a>
        </CardContent>
      </Card>
      <footer className="pt-2 text-center text-xs text-slate-500">
        Powered by HALA.wtf · <Link className="text-emerald-700" href="/register">Il tuo brand vuole HALA? Inizia gratis →</Link>
      </footer>
    </main>
  );
}
