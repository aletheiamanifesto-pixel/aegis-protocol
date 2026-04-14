"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { createProduct } from "@/lib/api";
import { useAuth } from "@/lib/auth";

const categories = ["Food & Beverage", "Skincare & Cosmetics", "Fashion & Textiles", "Electronics", "Furniture", "Other"];

export default function NewProductPage() {
  const { auth } = useAuth();
  const router = useRouter();
  const [form, setForm] = useState({ product_id: "", product_name: "", category: "Food & Beverage" });
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!auth) return;
    setError("");
    if (!form.product_id || !form.product_name) return setError("Product ID and name are required.");
    setLoading(true);
    try {
      await createProduct(form, auth.apiKey);
      router.push(`/dashboard/dpp/new?productId=${encodeURIComponent(form.product_id)}&productName=${encodeURIComponent(form.product_name)}&category=${encodeURIComponent(form.category)}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Product creation failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <Card className="max-w-2xl">
      <CardHeader><CardTitle>Create new product</CardTitle></CardHeader>
      <CardContent>
        <form onSubmit={onSubmit} className="space-y-4">
          <div><Label>Product ID / SKU</Label><Input value={form.product_id} onChange={(e) => setForm({ ...form, product_id: e.target.value })} required /></div>
          <div><Label>Product Name</Label><Input value={form.product_name} onChange={(e) => setForm({ ...form, product_name: e.target.value })} required /></div>
          <div>
            <Label>Category</Label>
            <Select value={form.category} onValueChange={(category) => setForm({ ...form, category })}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>{categories.map((cat) => <SelectItem key={cat} value={cat}>{cat}</SelectItem>)}</SelectContent>
            </Select>
          </div>
          {error && <p className="text-sm text-red-600">{error}</p>}
          <Button disabled={loading}>{loading ? "Creating..." : "Create Product"}</Button>
        </form>
      </CardContent>
    </Card>
  );
}
