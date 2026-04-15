import Link from "next/link";
import { ArrowRight, Blocks, Bot, ShieldCheck } from "lucide-react";

import { Header } from "@/components/header";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

const features = [
  { icon: ShieldCheck, title: "Autenticità verificata on-chain" },
  { icon: Blocks, title: "Blockchain immutabile (Polygon)" },
  { icon: Bot, title: "AI Auto-fill da documenti" }
];

export default function HomePage() {
  return (
    <div>
      <Header />
      <main>
        <section className="bg-gradient-to-b from-emerald-950 via-emerald-900 to-emerald-800 px-4 py-20 text-white">
          <div className="mx-auto max-w-6xl text-center">
            <h1 className="text-4xl font-bold md:text-5xl">Il passaporto digitale per i tuoi prodotti</h1>
            <p className="mx-auto mt-4 max-w-2xl text-emerald-100">Obbligatorio in EU dal 2026. Con HALA lo crei in 5 minuti.</p>
            <div className="mt-8 flex flex-wrap justify-center gap-3">
              <Link href="/register">
                <Button size="lg">Inizia Gratis</Button>
              </Link>
              <a href="#">
                <Button size="lg" variant="outline">Prenota Demo</Button>
              </a>
            </div>
          </div>
        </section>

        <section className="mx-auto grid max-w-6xl gap-4 px-4 py-12 md:grid-cols-3">
          {features.map((feature) => (
            <Card key={feature.title}>
              <CardHeader>
                <feature.icon className="h-8 w-8 text-emerald-600" />
                <CardTitle>{feature.title}</CardTitle>
              </CardHeader>
            </Card>
          ))}
        </section>

        <section className="mx-auto max-w-4xl px-4 py-8 text-center">
          <h2 className="text-2xl font-semibold">Come funziona</h2>
          <div className="mt-6 grid gap-4 md:grid-cols-3">
            {["Registra il tuo brand (5 min)", "Crea il DPP con AI (2 min)", "Stampa il QR sul prodotto (1 min)"].map((step, idx) => (
              <Card key={step}>
                <CardContent className="p-6 text-sm">
                  <p className="font-semibold text-emerald-700">Step {idx + 1}</p>
                  <p className="mt-2">{step}</p>
                </CardContent>
              </Card>
            ))}
          </div>
        </section>

        <section className="bg-white px-4 py-10 text-center">
          <p className="text-slate-600">Usato da brand in 🇮🇹 Italia, 🇫🇷 Francia, 🇩🇪 Germania</p>
          <div className="mx-auto mt-4 grid max-w-3xl grid-cols-3 gap-2 text-xs text-slate-400">
            <div className="rounded border border-dashed p-4">Logo 1</div>
            <div className="rounded border border-dashed p-4">Logo 2</div>
            <div className="rounded border border-dashed p-4">Logo 3</div>
          </div>
        </section>

        <section className="mx-auto max-w-4xl px-4 py-14 text-center">
          <h3 className="text-3xl font-bold">Gratis per i primi 20 brand. Poi €49/mese.</h3>
          <Link href="/register">
            <Button className="mt-6" size="lg">
              Inizia Gratis <ArrowRight className="ml-2 h-4 w-4" />
            </Button>
          </Link>
        </section>
      </main>

      <footer className="border-t border-slate-200 bg-white px-4 py-8">
        <div className="mx-auto flex max-w-6xl flex-col gap-3 text-sm text-slate-600 md:flex-row md:items-center md:justify-between">
          <div className="flex gap-4">
            <Link href="/pricing">Pricing</Link>
            <a href="#">Blog</a>
            <a href="#">Docs</a>
            <a href="#">Contact</a>
          </div>
          <p>© 2026 HALA.wtf — Digital Product Passports</p>
        </div>
      </footer>
    </div>
  );
}
