"use client";

import { useRouter } from "next/navigation";
import { FormEvent, useEffect, useState } from "react";

import { Header } from "@/components/header";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select } from "@/components/ui/select";
import { registerBrand } from "@/lib/api";

export default function RegisterPage() {
  const router = useRouter();
  const [loading, setLoading] = useState(false);
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [plan, setPlan] = useState("free");

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    if (params.get("plan") === "pro") {
      setPlan("pro");
    }
  }, []);

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    try {
      setLoading(true);
      const response = await registerBrand({ name, email, plan: plan as "free" | "pro" });
      localStorage.setItem("hala_api_key", response.api_key);
      localStorage.setItem("hala_brand_id", String(response.brand_id));
      localStorage.setItem("hala_brand_name", response.name);
      localStorage.setItem("hala_brand_email", response.email);
      localStorage.setItem("hala_plan", response.plan);
      router.push("/dashboard");
    } catch (error) {
      window.alert(error instanceof Error ? error.message : "Registrazione fallita");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <Header />
      <main className="mx-auto max-w-xl px-4 py-12">
        <Card>
          <CardHeader>
            <CardTitle>Registra il tuo brand</CardTitle>
          </CardHeader>
          <CardContent>
            <form className="space-y-4" onSubmit={onSubmit}>
              <div className="space-y-2">
                <Label htmlFor="name">Nome del Brand</Label>
                <Input id="name" onChange={(e) => setName(e.target.value)} required value={name} />
              </div>
              <div className="space-y-2">
                <Label htmlFor="email">Email</Label>
                <Input id="email" onChange={(e) => setEmail(e.target.value)} required type="email" value={email} />
              </div>
              <div className="space-y-2">
                <Label htmlFor="plan">Piano</Label>
                <Select id="plan" onChange={(e) => setPlan(e.target.value)} value={plan}>
                  <option value="free">free</option>
                  <option value="pro">pro</option>
                </Select>
              </div>
              <Button className="w-full" disabled={loading} type="submit">
                {loading ? "Caricamento..." : "Registrati →"}
              </Button>
            </form>
          </CardContent>
        </Card>
      </main>
    </div>
  );
}
