"use client";

import { useState } from "react";
import { Copy, Download } from "lucide-react";

import { Button } from "@/components/ui/button";

export function QrDisplay({ verifyUrl }: { verifyUrl: string }) {
  const qrUrl = `https://quickchart.io/qr?size=240&text=${encodeURIComponent(verifyUrl)}`;
  const [copied, setCopied] = useState(false);

  const copy = async () => {
    await navigator.clipboard.writeText(verifyUrl);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-4 rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
      <img alt="QR verifica prodotto" className="mx-auto h-56 w-56 rounded" src={qrUrl} />
      <p className="break-all text-center text-xs text-slate-500">{verifyUrl}</p>
      <div className="flex gap-2">
        <a className="flex-1" download="hala-qr.png" href={qrUrl}>
          <Button className="w-full" variant="outline">
            <Download className="mr-2 h-4 w-4" /> Scarica QR PNG
          </Button>
        </a>
        <Button className="flex-1" onClick={copy} variant="secondary">
          <Copy className="mr-2 h-4 w-4" /> Copia Link
        </Button>
      </div>
      {copied && <p className="text-center text-xs text-emerald-700">Link copiato</p>}
    </div>
  );
}
