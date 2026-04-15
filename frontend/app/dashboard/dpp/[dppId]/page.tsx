"use client";

import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useQuery } from "@tanstack/react-query";

import { QrDisplay } from "@/components/qr-display";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { getDPP, revokeDPP } from "@/lib/api";

export default function DppDetailPage() {
  const params = useParams<{ dppId: string }>();
  const router = useRouter();
  const dppId = Number(params.dppId);

  const dppQuery = useQuery({ queryKey: ["dpp", dppId], queryFn: () => getDPP(dppId), enabled: !!dppId });

  if (dppQuery.isLoading) return <p>Caricamento...</p>;
  if (dppQuery.error || !dppQuery.data) return <p className="text-red-500">Impossibile caricare DPP</p>;

  const dpp = dppQuery.data;
  const verifyUrl = typeof window !== "undefined" ? `${window.location.origin}/verify/${dpp.productId}` : dpp.verification_url;

  return (
    <div className="space-y-4">
      <div className="grid gap-4 lg:grid-cols-[320px_1fr]">
        <QrDisplay verifyUrl={verifyUrl} />
        <Card>
          <CardHeader><CardTitle>{dpp.productName}</CardTitle></CardHeader>
          <CardContent className="space-y-3 text-sm">
            <p><strong>Product ID:</strong> {dpp.productId}</p>
            <p><strong>Categoria:</strong> {dpp.category}</p>
            <p><strong>Versione:</strong> {dpp.version}</p>
            <p><strong>Materiali:</strong> {(dpp.materials || []).join(", ")}</p>
            <p><strong>Origine:</strong> {dpp.origin_country}</p>
            <p><strong>Istruzioni riciclo:</strong> {dpp.recycling_instructions || "-"}</p>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader><CardTitle>Blockchain proof</CardTitle></CardHeader>
        <CardContent className="space-y-2 text-xs">
          <p className="break-all"><strong>Hash:</strong> {dpp.dpp_hash}</p>
          <p className="break-all"><strong>Tx:</strong> {dpp.blockchain_tx}</p>
          <p className="break-all"><strong>IPFS CID:</strong> {dpp.ipfs_cid}</p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle>Compliance</CardTitle></CardHeader>
        <CardContent>
          <p className="text-sm">I dati inseriti sono pronti per verifica consumer e audit.</p>
          <div className="mt-3 flex flex-wrap gap-2">
            <Button variant="outline">✏️ Modifica</Button>
            <Button
              onClick={async () => {
                if (!window.confirm("Revocare questo DPP?")) return;
                await revokeDPP(dppId);
                window.alert("DPP revocato");
                router.push("/dashboard");
              }}
              variant="destructive"
            >
              🗑️ Revoca
            </Button>
            <Link href={`/verify/${dpp.productId}`} target="_blank"><Button>👁️ Anteprima Consumer</Button></Link>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
