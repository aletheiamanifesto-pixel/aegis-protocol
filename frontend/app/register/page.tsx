"use client";

import { useEffect, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { Copy } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { registerBrand } from "@/lib/api";
import { getAuth, setAuth } from "@/lib/auth";

export default function RegisterPage() {
  const [form, setForm] = useState({
    name: "",
    email: "",
    password: "",
    plan: "free" as "free" | "pro",
    address: "",
    country: "",
    phone: "",
    website: "",
    operator_type: "manufacturer" as "manufacturer" | "importer"
  });
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [apiKey, setApiKey] = useState("");
  const router = useRouter();
  const params = useSearchParams();

  useEffect(() => {
    if (getAuth()) router.replace("/dashboard");
    const plan = params.get("plan");
    if (plan === "pro") setForm((p) => ({ ...p, plan: "pro" }));
  }, [router, params]);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    if (!form.name || !form.email || !form.password) return setError("Name, email, and password are required.");
    setLoading(true);
    try {
      const data = await registerBrand(form);
      localStorage.setItem("hala_email", form.email);
      setAuth({ apiKey: data.api_key, brandId: data.brand_id, brandName: data.name, plan: data.plan });
      setApiKey(data.api_key);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Registration failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="container max-w-xl py-10">
      <Card>
        <CardHeader><CardTitle>Register your brand</CardTitle></CardHeader>
        <CardContent>
          <form onSubmit={onSubmit} className="space-y-4">
            <div><Label>Brand name</Label><Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required /></div>
            <div><Label>Email</Label><Input type="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} required /></div>
            <div><Label>Password</Label><Input type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} required /></div>
            <div><Label>Plan</Label><div className="mt-2 flex gap-4 text-sm"><label><input type="radio" checked={form.plan === "free"} onChange={() => setForm({ ...form, plan: "free" })} /> Free</label><label><input type="radio" checked={form.plan === "pro"} onChange={() => setForm({ ...form, plan: "pro" })} /> Pro</label></div></div>
            <div><Label>Address (optional)</Label><Input value={form.address} onChange={(e) => setForm({ ...form, address: e.target.value })} /></div>
            <div className="grid gap-4 sm:grid-cols-2"><div><Label>Country (optional)</Label><Input value={form.country} onChange={(e) => setForm({ ...form, country: e.target.value })} /></div><div><Label>Phone (optional)</Label><Input value={form.phone} onChange={(e) => setForm({ ...form, phone: e.target.value })} /></div></div>
            <div><Label>Website (optional)</Label><Input value={form.website} onChange={(e) => setForm({ ...form, website: e.target.value })} /></div>
            <div><Label>Operator type</Label><div className="mt-2 flex gap-4 text-sm"><label><input type="radio" checked={form.operator_type === "manufacturer"} onChange={() => setForm({ ...form, operator_type: "manufacturer" })} /> Manufacturer</label><label><input type="radio" checked={form.operator_type === "importer"} onChange={() => setForm({ ...form, operator_type: "importer" })} /> Importer</label></div></div>
            {error && <p className="text-sm text-red-600">{error}</p>}
            <Button type="submit" className="w-full" disabled={loading}>{loading ? "Creating account..." : "Create account"}</Button>
          </form>

          {apiKey && (
            <Card className="mt-5 border-green-300">
              <CardContent className="space-y-2 p-4">
                <p className="font-semibold text-green-700">IMPORTANT: Copy this API key now — it cannot be retrieved later.</p>
              <div className="flex gap-2">
                <Input value={apiKey} readOnly />
                <Button type="button" variant="outline" onClick={() => navigator.clipboard.writeText(apiKey)}><Copy className="h-4 w-4" /></Button>
              </div>
              <Button type="button" onClick={() => router.push("/dashboard")}>Continue to dashboard</Button>
            </CardContent>
          </Card>
          )}
        </CardContent>
      </Card>
    </main>
  );
}
