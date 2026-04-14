import Link from "next/link";
import { Brain, Scale, ShieldCheck } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";

const features = [
  {
    icon: ShieldCheck,
    title: "Blockchain Verified",
    copy: "Every passport is hashed and registered on Polygon. Impossible to fake."
  },
  {
    icon: Brain,
    title: "AI-Powered",
    copy: "Upload your documents. Our AI fills 80% of the passport automatically."
  },
  {
    icon: Scale,
    title: "EU Compliant",
    copy: "Full ESPR compliance with 8 mandatory data areas covered."
  }
];

export default function HomePage() {
  return (
    <main className="min-h-screen bg-white text-slate-900">
      <section className="bg-gradient-to-b from-green-50 via-white to-white">
        <div className="container py-16 md:py-24">
          <div className="mx-auto max-w-3xl text-center">
            <h1 className="text-4xl font-bold tracking-tight md:text-6xl">Every product deserves a digital identity.</h1>
            <p className="mt-4 text-lg text-slate-600 md:text-xl">EU regulation makes Digital Product Passports mandatory from 2026. HALA creates yours in 5 minutes.</p>
            <div className="mt-8 flex flex-col justify-center gap-3 sm:flex-row">
              <Button asChild size="lg">
                <Link href="/register">Start Free →</Link>
              </Button>
              <Button variant="outline" asChild size="lg">
                <Link href="/verify/demo-product">See a live demo →</Link>
              </Button>
            </div>
          </div>
        </div>
      </section>

      <section className="container py-14">
        <div className="grid gap-4 md:grid-cols-3">
          {features.map((feature) => (
            <Card key={feature.title}>
              <CardContent className="space-y-3 p-6">
                <feature.icon className="h-7 w-7 text-green-600" />
                <h3 className="text-xl font-semibold">{feature.title}</h3>
                <p className="text-slate-600">{feature.copy}</p>
              </CardContent>
            </Card>
          ))}
        </div>
      </section>

      <section className="container py-12">
        <h2 className="text-2xl font-semibold">How it works</h2>
        <div className="mt-6 grid gap-4 md:grid-cols-3">
          <Card><CardContent className="p-6"><p className="font-semibold">1. Register your brand</p><p className="text-sm text-slate-600">30 seconds</p></CardContent></Card>
          <Card><CardContent className="p-6"><p className="font-semibold">2. Add your product data</p><p className="text-sm text-slate-600">AI assists you</p></CardContent></Card>
          <Card><CardContent className="p-6"><p className="font-semibold">3. Get your QR code</p><p className="text-sm text-slate-600">Print it on your packaging</p></CardContent></Card>
        </div>
      </section>

      <section className="container py-12 text-center">
        <p className="text-sm uppercase tracking-widest text-slate-500">Social proof</p>
        <p className="mt-2 text-xl font-medium">Trusted by [X] brands · Products verified: [X]</p>
      </section>

      <section className="container py-14 text-center">
        <h2 className="text-3xl font-semibold">Ready to protect your products?</h2>
        <Button className="mt-6" size="lg" asChild>
          <Link href="/register">Start Free</Link>
        </Button>
      </section>

      <footer className="border-t py-8">
        <div className="container flex flex-col items-center justify-between gap-3 text-sm text-slate-600 md:flex-row">
          <div className="flex gap-4">
            <Link href="/pricing">Pricing</Link>
            <Link href="#">Blog</Link>
            <Link href="/docs">API Docs</Link>
            <Link href="#">Contact</Link>
          </div>
          <p>Powered by blockchain. Built for humans.</p>
        </div>
      </footer>
    </main>
  );
}
