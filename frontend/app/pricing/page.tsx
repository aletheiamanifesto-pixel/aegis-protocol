import Link from "next/link";
import { Check } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

const starter = ["5 products", "QR code generation", "Public verification page", "Basic compliance check", "HALA verified badge"];
const pro = ["500 products", "Everything in Starter", "AI auto-fill from documents", "Advanced analytics", "Custom branding on verify page", "API access", "Priority support"];

export default function PricingPage() {
  return (
    <main className="container py-12">
      <h1 className="text-center text-4xl font-bold">Simple pricing for every brand</h1>
      <div className="mt-10 grid gap-6 md:grid-cols-2">
        <Card>
          <CardHeader><CardTitle>Starter — Free</CardTitle></CardHeader>
          <CardContent className="space-y-3">
            {starter.map((item) => <p key={item} className="flex items-center gap-2"><Check className="h-4 w-4 text-green-600" />{item}</p>)}
            <Button asChild className="mt-6 w-full"><Link href="/register">Start Free →</Link></Button>
          </CardContent>
        </Card>
        <Card className="border-green-500">
          <CardHeader><CardTitle>Pro — €49/month</CardTitle></CardHeader>
          <CardContent className="space-y-3">
            {pro.map((item) => <p key={item} className="flex items-center gap-2"><Check className="h-4 w-4 text-green-600" />{item}</p>)}
            <Button asChild className="mt-6 w-full"><Link href="/register?plan=pro">Start 14-day trial →</Link></Button>
            <p className="text-xs text-slate-500">No credit card required for trial</p>
          </CardContent>
        </Card>
      </div>
    </main>
  );
}
