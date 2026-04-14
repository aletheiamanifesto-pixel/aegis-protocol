"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { Copy } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { useAuth } from "@/lib/auth";

export default function SettingsPage() {
  const { auth } = useAuth();
  const [email, setEmail] = useState("N/A");

  useEffect(() => {
    const stored = localStorage.getItem("hala_email");
    if (stored) setEmail(stored);
  }, []);

  if (!auth) return null;

  const limit = auth.plan === "pro" ? 500 : 5;
  const used = 0;
  const percent = (used / limit) * 100;

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader><CardTitle>Brand info</CardTitle></CardHeader>
        <CardContent className="space-y-2 text-sm">
          <p><strong>Name:</strong> {auth.brandName}</p>
          <p><strong>Email:</strong> {email}</p>
          <p><strong>Address:</strong> Read only for now</p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle>API Key</CardTitle></CardHeader>
        <CardContent>
          <div className="flex gap-2">
            <Input readOnly value={auth.apiKey} />
            <Button variant="outline" onClick={() => navigator.clipboard.writeText(auth.apiKey)}><Copy className="h-4 w-4" /></Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle>Plan & usage</CardTitle></CardHeader>
        <CardContent className="space-y-3 text-sm">
          <p>Current plan: <strong>{auth.plan.toUpperCase()}</strong></p>
          <p>{used}/{limit} products used</p>
          <div className="h-2 rounded-full bg-slate-100"><div className="h-2 rounded-full bg-green-600" style={{ width: `${percent}%` }} /></div>
          <Button asChild><Link href="/pricing">Upgrade plan</Link></Button>
        </CardContent>
      </Card>
    </div>
  );
}
