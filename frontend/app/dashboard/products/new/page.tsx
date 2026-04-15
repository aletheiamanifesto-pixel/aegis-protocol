"use client";

import { FormEvent, useState } from "react";
import { useRouter } from "next/navigation";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select } from "@/components/ui/select";
import { createProduct } from "@/lib/api";

const categories = ["Food & Beverage", "Skincare", "Fashion", "Electronics", "Furniture", "Other"];

export default function CreateProductPage() {
  const router = useRouter();
  const [name, setName] = useState("");
  const [sku, setSku] = useState("");
  const [category, setCategory] = useState(categories[1]);
  const [loading, setLoading] = useState(false);

  const save = async (createDpp = false) => {
    try {
      setLoading(true);
      await createProduct({ product_name: name, product_id: sku, category });
      if (createDpp) {
        router.push(`/dashboard/dpp/new?productId=${encodeURIComponent(sku)}`);
      } else {
        router.push("/dashboard");
      }
    } catch (error) {
      window.alert(error instanceof Error ? error.message : "Errore salvataggio prodotto");
    } finally {
      setLoading(false);
    }
  };

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    await save(false);
  };

  return (
    <Card className="max-w-2xl">
      <CardHeader><CardTitle>Nuovo prodotto</CardTitle></CardHeader>
      <CardContent>
        <form className="space-y-4" onSubmit={onSubmit}>
          <div className="space-y-2"><Label>Nome prodotto</Label><Input onChange={(e) => setName(e.target.value)} required value={name} /></div>
          <div className="space-y-2"><Label>SKU / Codice prodotto</Label><Input onChange={(e) => setSku(e.target.value)} required value={sku} /></div>
          <div className="space-y-2">
            <Label>Categoria</Label>
            <Select onChange={(e) => setCategory(e.target.value)} value={category}>
              {categories.map((option) => <option key={option}>{option}</option>)}
            </Select>
          </div>
          <div className="flex flex-wrap gap-2">
            <Button disabled={loading} type="submit">Salva Prodotto</Button>
            <Button disabled={loading} onClick={() => save(true)} type="button" variant="secondary">Salva e Crea DPP →</Button>
          </div>
        </form>
      </CardContent>
    </Card>
  );
}
