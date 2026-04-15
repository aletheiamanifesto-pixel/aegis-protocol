"use client";

import Link from "next/link";
import { Eye, EyeOff } from "lucide-react";
import { FormEvent, useState } from "react";
import { useRouter } from "next/navigation";

import { Header } from "@/components/header";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";

export default function LoginPage() {
  const router = useRouter();
  const [apiKey, setApiKey] = useState("");
  const [show, setShow] = useState(false);

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (!apiKey.trim()) {
      window.alert("Inserisci una API key valida");
      return;
    }
    localStorage.setItem("hala_api_key", apiKey.trim());
    router.push("/dashboard");
  };

  return (
    <div>
      <Header />
      <main className="mx-auto max-w-xl px-4 py-12">
        <Card>
          <CardHeader>
            <CardTitle>Inserisci la tua API Key per accedere alla dashboard</CardTitle>
          </CardHeader>
          <CardContent>
            <form className="space-y-4" onSubmit={onSubmit}>
              <div className="relative">
                <Input
                  onChange={(e) => setApiKey(e.target.value)}
                  placeholder="sk_live_..."
                  type={show ? "text" : "password"}
                  value={apiKey}
                />
                <button className="absolute right-3 top-2.5 text-slate-500" onClick={() => setShow((v) => !v)} type="button">
                  {show ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
              <Button className="w-full" type="submit">Accedi →</Button>
            </form>
            <p className="mt-4 text-sm text-slate-600">
              Non hai un account? <Link className="text-emerald-700" href="/register">Registrati</Link>
            </p>
          </CardContent>
        </Card>
      </main>
    </div>
  );
}
