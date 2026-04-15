import Link from "next/link";

import { Header } from "@/components/header";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export default function PricingPage() {
  return (
    <div>
      <Header />
      <main className="mx-auto max-w-6xl px-4 py-12">
        <h1 className="text-center text-3xl font-bold">Prezzi semplici</h1>
        <div className="mt-8 grid gap-4 md:grid-cols-2">
          <Card>
            <CardHeader>
              <CardTitle>STARTER (Gratis)</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-sm text-slate-600">
              <p>5 prodotti</p>
              <p>QR code base</p>
              <p>Verifica pubblica</p>
              <p>Badge "HALA verified"</p>
              <Link href="/register">
                <Button className="mt-4 w-full">Inizia Gratis →</Button>
              </Link>
            </CardContent>
          </Card>
          <Card className="border-emerald-200">
            <CardHeader>
              <Badge className="w-fit">Più popolare</Badge>
              <CardTitle>PRO (€49/mese)</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-sm text-slate-600">
              <p>500 prodotti</p>
              <p>QR + NFC support</p>
              <p>AI auto-fill</p>
              <p>Analytics dashboard</p>
              <p>EU ESPR compliance</p>
              <p>Custom branding</p>
              <p>API access</p>
              <p>Priority support</p>
              <Link href="/register?plan=pro">
                <Button className="mt-4 w-full">Prova 14 giorni gratis →</Button>
              </Link>
            </CardContent>
          </Card>
        </div>
      </main>
    </div>
  );
}
