"use client";

import Link from "next/link";
import { useEffect, useMemo, useRef, useState } from "react";
import { useParams } from "next/navigation";
import { Copy, Download, Eye, Trash2 } from "lucide-react";
import { QRCodeSVG } from "qrcode.react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { getDPP, revokeDPP, type DPPDetailResponse } from "@/lib/api";
import { useAuth } from "@/lib/auth";

export default function DppDetailPage() {
  const params = useParams<{ dppId: string }>();
  const { auth } = useAuth();
  const [data, setData] = useState<DPPDetailResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const qrWrapRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    async function run() {
      try {
        const dpp = await getDPP(Number(params.dppId));
        setData(dpp);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load DPP");
      } finally {
        setLoading(false);
      }
    }
    run();
  }, [params.dppId]);

  const verifyUrl = useMemo(
    () => `${typeof window === "undefined" ? "" : window.location.origin}/verify/${data?.productId || ""}`,
    [data?.productId]
  );

  if (loading) return <div className="h-64 animate-pulse rounded-lg bg-white" />;
  if (error || !data) return <p className="text-red-600">{error || "DPP not found"}</p>;

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader><CardTitle>DPP #{params.dppId}</CardTitle></CardHeader>
        <CardContent className="space-y-4">
          <div className="flex flex-col gap-4 sm:flex-row sm:items-center">
            <div className="rounded-lg border p-3" ref={qrWrapRef}><QRCodeSVG value={verifyUrl} size={140} /></div>
            <div className="space-y-2">
              <Button variant="outline" onClick={() => navigator.clipboard.writeText(verifyUrl)}><Copy className="mr-2 h-4 w-4" />Copy verification URL</Button>
              <Button variant="outline" onClick={() => {
                const svg = qrWrapRef.current?.querySelector("svg");
                if (!svg) return;
                const serializer = new XMLSerializer();
                const source = serializer.serializeToString(svg);
                const blob = new Blob([source], { type: "image/svg+xml;charset=utf-8" });
                const url = URL.createObjectURL(blob);
                const a = document.createElement("a");
                a.href = url;
                a.download = `hala-dpp-${params.dppId}.svg`;
                a.click();
              }}><Download className="mr-2 h-4 w-4" />Download QR SVG</Button>
              <Button variant="outline" onClick={() => {
                const svg = qrWrapRef.current?.querySelector("svg");
                if (!svg) return;
                const canvas = document.createElement("canvas");
                canvas.width = 512;
                canvas.height = 512;
                const ctx = canvas.getContext("2d");
                const img = new Image();
                const xml = new XMLSerializer().serializeToString(svg);
                const blob = new Blob([xml], { type: "image/svg+xml;charset=utf-8" });
                const url = URL.createObjectURL(blob);
                img.onload = () => {
                  ctx?.drawImage(img, 0, 0, 512, 512);
                  const png = canvas.toDataURL("image/png");
                  const a = document.createElement("a");
                  a.href = png;
                  a.download = `hala-dpp-${params.dppId}.png`;
                  a.click();
                  URL.revokeObjectURL(url);
                };
                img.src = url;
              }}><Download className="mr-2 h-4 w-4" />Download QR PNG</Button>
            </div>
          </div>
          <Separator />
          <div className="grid gap-3 text-sm">
            <p><strong>Product:</strong> {data.productName}</p>
            <p><strong>Category:</strong> {data.category}</p>
            <p><strong>Materials:</strong> {(data.materials || []).join(", ") || "N/A"}</p>
            <p><strong>Origin:</strong> {data.origin_country}</p>
            <p><strong>Certifications:</strong> {(data.certifications || []).join(", ") || "N/A"}</p>
            <p><strong>Recyclability:</strong> {data.recyclability_percent ?? "N/A"}%</p>
          </div>
          <Separator />
          <div className="space-y-1 text-sm">
            <p><strong>Hash:</strong> {data.dpp_hash}</p>
            <p><strong>Tx:</strong> <a className="text-green-700 underline" href={data.blockchain_tx} target="_blank" rel="noreferrer">{data.blockchain_tx}</a></p>
            <p><strong>IPFS:</strong> <a className="text-green-700 underline" href={`https://ipfs.io/ipfs/${data.ipfs_cid}`} target="_blank" rel="noreferrer">{data.ipfs_cid}</a></p>
          </div>
          <Separator />
          <div className="flex flex-wrap gap-2">
            <div className="rounded-md border px-3 py-2 text-sm text-slate-500">Edit DPP (coming soon)</div>
            <Button variant="destructive" onClick={async () => {
              if (!auth) return;
              if (!confirm("Revoke this DPP?")) return;
              await revokeDPP(Number(params.dppId), auth.apiKey);
              setData((prev) => (prev ? { ...prev, is_active: false } : prev));
            }}><Trash2 className="mr-2 h-4 w-4" />Revoke DPP</Button>
            <Button variant="outline" asChild><Link href={`/verify/${data.productId}`} target="_blank"><Eye className="mr-2 h-4 w-4" />Preview Consumer View</Link></Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
