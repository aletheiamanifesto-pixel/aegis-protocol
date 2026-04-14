"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { getBrandStats } from "@/lib/api";
import { getAuth, setAuth } from "@/lib/auth";

export default function LoginPage() {
  const [email, setEmail] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [brandId, setBrandId] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const router = useRouter();

  useEffect(() => {
    if (getAuth()) router.replace("/dashboard");
    const cached = localStorage.getItem("hala_email");
    if (cached) setEmail(cached);
  }, [router]);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    if (!email || !apiKey || !brandId) return setError("Email, API key, and brand ID are required.");
    setLoading(true);
    const numericBrandId = Number(brandId);
    if (!Number.isInteger(numericBrandId) || numericBrandId <= 0) {
      setError("Brand ID must be a positive number.");
      setLoading(false);
      return;
    }
    try {
      await getBrandStats(numericBrandId, apiKey);
    } catch {
      setError("Could not validate this API key.");
      setLoading(false);
      return;
    }
    setAuth({ apiKey, brandId: numericBrandId, brandName: `Brand #${numericBrandId}`, plan: "free" });
    localStorage.setItem("hala_email", email);
    router.push("/dashboard");
  }

  return (
    <main className="container max-w-md py-10">
      <Card>
        <CardHeader><CardTitle>Brand login</CardTitle></CardHeader>
        <CardContent>
          <form className="space-y-4" onSubmit={onSubmit}>
            <div><Label>Email</Label><Input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required /></div>
            <div><Label>API Key</Label><Input value={apiKey} onChange={(e) => setApiKey(e.target.value)} required /></div>
            <div><Label>Brand ID</Label><Input value={brandId} onChange={(e) => setBrandId(e.target.value)} required /></div>
            {error && <p className="text-sm text-red-600">{error}</p>}
            <Button className="w-full" disabled={loading}>{loading ? "Validating..." : "Login"}</Button>
          </form>
          <p className="mt-4 text-sm text-slate-600">New brand? <Link href="/register" className="text-green-700 underline">Create account</Link></p>
        </CardContent>
      </Card>
    </main>
  );
}
