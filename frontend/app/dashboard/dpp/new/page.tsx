"use client";

import { FormEvent, useMemo, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { useQuery } from "@tanstack/react-query";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { createDPP, listBrandProducts, verifyProduct, type DPPCreateInput } from "@/lib/api";

function parseTags(value: string) {
  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

export default function CreateDppPage() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const brandId = typeof window !== "undefined" ? Number(localStorage.getItem("hala_brand_id") || 0) : 0;
  const brandName = typeof window !== "undefined" ? localStorage.getItem("hala_brand_name") || "" : "";

  const [form, setForm] = useState<DPPCreateInput>({
    productId: searchParams.get("productId") || "",
    productName: "",
    category: "Skincare",
    materials: [],
    origin_country: "IT",
    brand_name: brandName,
    certifications: [],
    materials_detailed: [],
    hazardous_substances: [],
    test_reports_urls: []
  });

  const productsQuery = useQuery({ queryKey: ["dpp-products", brandId], queryFn: () => listBrandProducts(brandId), enabled: !!brandId });

  const requiredFields = ["productId", "productName", "materials", "origin_country", "operator_type", "certifications", "carbon_footprint_kg", "expected_lifetime_years", "recycling_instructions", "recyclability_percent", "model_variant"] as const;

  const compliance = useMemo(() => {
    const missing = requiredFields.filter((key) => {
      const value = form[key as keyof DPPCreateInput];
      if (Array.isArray(value)) return value.length === 0;
      return value === undefined || value === null || value === "";
    });
    const score = Math.round(((requiredFields.length - missing.length) / requiredFields.length) * 100);
    return { score, missing };
  }, [form]);

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    try {
      await createDPP({ ...form, brand_name: brandName || form.brand_name });
      const verification = await verifyProduct(form.productId);
      const dppId = Number((verification.passport_data as { dpp_id?: number } | null)?.dpp_id || 0);
      if (dppId) {
        router.push(`/dashboard/dpp/${dppId}`);
        return;
      }
      router.push("/dashboard");
    } catch (error) {
      window.alert(error instanceof Error ? error.message : "Errore creazione DPP");
    }
  };

  return (
    <div className="grid gap-4 lg:grid-cols-[1fr_300px]">
      <Card>
        <CardHeader><CardTitle>Crea DPP</CardTitle></CardHeader>
        <CardContent>
          <form className="space-y-4" onSubmit={onSubmit}>
            <div className="space-y-2">
              <Label>Seleziona prodotto</Label>
              <Select
                onChange={(e) => {
                  const selected = productsQuery.data?.find((p) => p.product_id === e.target.value);
                  setForm((prev) => ({ ...prev, productId: e.target.value, productName: selected?.product_name || prev.productName, category: selected?.category || prev.category }));
                }}
                value={form.productId}
              >
                <option value="">Seleziona...</option>
                {(productsQuery.data || []).map((product) => (
                  <option key={product.id} value={product.product_id}>{product.product_name} ({product.product_id})</option>
                ))}
              </Select>
            </div>
            <div className="grid gap-3 md:grid-cols-2">
              <div className="space-y-2"><Label>Nome prodotto</Label><Input onChange={(e) => setForm({ ...form, productName: e.target.value })} value={form.productName} /></div>
              <div className="space-y-2"><Label>Categoria</Label><Input onChange={(e) => setForm({ ...form, category: e.target.value })} value={form.category} /></div>
            </div>

            <details open>
              <summary className="cursor-pointer font-semibold">Section 1: Materiali e Composizione</summary>
              <div className="mt-3 grid gap-3">
                <Input placeholder="materials (comma separated)" onChange={(e) => setForm({ ...form, materials: parseTags(e.target.value) })} />
                <Input placeholder="recycled_content_percent" type="number" onChange={(e) => setForm({ ...form, recycled_content_percent: Number(e.target.value) || undefined })} />
                <div className="rounded border border-slate-200 p-3">
                  <p className="mb-2 text-sm font-medium">materials_detailed</p>
                  {(form.materials_detailed || []).map((material, index) => (
                    <div className="mb-2 grid gap-2 md:grid-cols-4" key={`material-${index}`}>
                      <Input placeholder="name" value={material.name} onChange={(e) => {
                        const next = [...(form.materials_detailed || [])];
                        next[index] = { ...next[index], name: e.target.value };
                        setForm({ ...form, materials_detailed: next });
                      }} />
                      <Input placeholder="weight%" type="number" value={material.weight_percent ?? ""} onChange={(e) => {
                        const next = [...(form.materials_detailed || [])];
                        next[index] = { ...next[index], weight_percent: Number(e.target.value) || undefined };
                        setForm({ ...form, materials_detailed: next });
                      }} />
                      <Input placeholder="recycled%" type="number" value={material.recycled_content_percent ?? ""} onChange={(e) => {
                        const next = [...(form.materials_detailed || [])];
                        next[index] = { ...next[index], recycled_content_percent: Number(e.target.value) || undefined };
                        setForm({ ...form, materials_detailed: next });
                      }} />
                      <Input placeholder="origin_country" value={material.origin_country ?? ""} onChange={(e) => {
                        const next = [...(form.materials_detailed || [])];
                        next[index] = { ...next[index], origin_country: e.target.value };
                        setForm({ ...form, materials_detailed: next });
                      }} />
                    </div>
                  ))}
                  <Button type="button" variant="outline" onClick={() => setForm({ ...form, materials_detailed: [...(form.materials_detailed || []), { name: "" }] })}>Aggiungi materiale dettagliato</Button>
                </div>
              </div>
            </details>

            <details open>
              <summary className="cursor-pointer font-semibold">Section 2: Origine e Operatore</summary>
              <div className="mt-3 grid gap-3 md:grid-cols-2">
                <Input placeholder="origin_country" value={form.origin_country} onChange={(e) => setForm({ ...form, origin_country: e.target.value })} />
                <Select value={form.operator_type || ""} onChange={(e) => setForm({ ...form, operator_type: e.target.value || undefined })}>
                  <option value="">operator_type</option>
                  <option value="manufacturer">manufacturer</option>
                  <option value="importer">importer</option>
                  <option value="authorized_representative">authorized_representative</option>
                </Select>
                <Input placeholder="operator_address" onChange={(e) => setForm({ ...form, operator_address: e.target.value })} />
                <Input placeholder="facility_id" onChange={(e) => setForm({ ...form, facility_id: e.target.value })} />
                {form.operator_type === "importer" && <Input placeholder="eori_number" onChange={(e) => setForm({ ...form, eori_number: e.target.value })} />}
              </div>
            </details>

            <details open>
              <summary className="cursor-pointer font-semibold">Section 3: Certificazioni e Conformità</summary>
              <div className="mt-3 grid gap-3">
                <Input placeholder="certifications (comma separated)" onChange={(e) => setForm({ ...form, certifications: parseTags(e.target.value) })} />
                <div className="grid gap-2 md:grid-cols-3 text-sm">
                  <label><input type="checkbox" checked={!!form.ce_marking} onChange={(e) => setForm({ ...form, ce_marking: e.target.checked })} /> ce_marking</label>
                  <label><input type="checkbox" checked={!!form.reach_compliant} onChange={(e) => setForm({ ...form, reach_compliant: e.target.checked })} /> reach_compliant</label>
                  <label><input type="checkbox" checked={!!form.rohs_compliant} onChange={(e) => setForm({ ...form, rohs_compliant: e.target.checked })} /> rohs_compliant</label>
                </div>
                <Input placeholder="conformity_declaration_url" type="url" onChange={(e) => setForm({ ...form, conformity_declaration_url: e.target.value })} />
                <Input placeholder="test_reports_urls (comma separated)" onChange={(e) => setForm({ ...form, test_reports_urls: parseTags(e.target.value) })} />
              </div>
            </details>

            <details open>
              <summary className="cursor-pointer font-semibold">Section 4: Impatto Ambientale</summary>
              <div className="mt-3 grid gap-3 md:grid-cols-2">
                <Input placeholder="carbon_footprint_kg" type="number" onChange={(e) => setForm({ ...form, carbon_footprint_kg: Number(e.target.value) || undefined })} />
                <Select value={form.carbon_footprint_method || ""} onChange={(e) => setForm({ ...form, carbon_footprint_method: e.target.value || undefined })}>
                  <option value="">carbon_footprint_method</option>
                  <option value="PEF">PEF</option>
                  <option value="ISO_14067">ISO_14067</option>
                  <option value="GHG_Protocol">GHG_Protocol</option>
                  <option value="estimated">estimated</option>
                </Select>
                <Input placeholder="energy_consumption_kwh" type="number" onChange={(e) => setForm({ ...form, energy_consumption_kwh: Number(e.target.value) || undefined })} />
                <Input placeholder="water_consumption_liters" type="number" onChange={(e) => setForm({ ...form, water_consumption_liters: Number(e.target.value) || undefined })} />
              </div>
            </details>

            <details open>
              <summary className="cursor-pointer font-semibold">Section 5: Durabilità e Garanzia</summary>
              <div className="mt-3 grid gap-3 md:grid-cols-2">
                <Input placeholder="expected_lifetime_years" type="number" onChange={(e) => setForm({ ...form, expected_lifetime_years: Number(e.target.value) || undefined })} />
                <Input placeholder="repair_score (0-10)" type="number" onChange={(e) => setForm({ ...form, repair_score: Number(e.target.value) || undefined })} />
                <label className="text-sm"><input type="checkbox" checked={!!form.spare_parts_available} onChange={(e) => setForm({ ...form, spare_parts_available: e.target.checked })} /> spare_parts_available</label>
                <Input placeholder="warranty_duration_months" type="number" onChange={(e) => setForm({ ...form, warranty_duration_months: Number(e.target.value) || undefined })} />
              </div>
              <Textarea className="mt-3" placeholder="warranty_terms" onChange={(e) => setForm({ ...form, warranty_terms: e.target.value })} />
              <Textarea className="mt-3" placeholder="maintenance_instructions" onChange={(e) => setForm({ ...form, maintenance_instructions: e.target.value })} />
            </details>

            <details open>
              <summary className="cursor-pointer font-semibold">Section 6: Circolarità e Fine Vita</summary>
              <div className="mt-3 grid gap-3 md:grid-cols-2">
                <Textarea placeholder="recycling_instructions" onChange={(e) => setForm({ ...form, recycling_instructions: e.target.value })} />
                <Input placeholder="recyclability_percent" type="number" onChange={(e) => setForm({ ...form, recyclability_percent: Number(e.target.value) || undefined })} />
                <Textarea placeholder="disassembly_instructions" onChange={(e) => setForm({ ...form, disassembly_instructions: e.target.value })} />
                <Input placeholder="collection_points_url" type="url" onChange={(e) => setForm({ ...form, collection_points_url: e.target.value })} />
                <Select value={form.reuse_potential || ""} onChange={(e) => setForm({ ...form, reuse_potential: e.target.value || undefined })}>
                  <option value="">reuse_potential</option>
                  <option value="high">high</option>
                  <option value="medium">medium</option>
                  <option value="low">low</option>
                  <option value="none">none</option>
                </Select>
              </div>
            </details>

            <details>
              <summary className="cursor-pointer font-semibold">Section 7: Commercio e Dogana</summary>
              <div className="mt-3 grid gap-3 md:grid-cols-2">
                <Input placeholder="hs_code" onChange={(e) => setForm({ ...form, hs_code: e.target.value })} />
                <Input placeholder="cn_code" onChange={(e) => setForm({ ...form, cn_code: e.target.value })} />
                <Input placeholder="product_image_url" type="url" onChange={(e) => setForm({ ...form, product_image_url: e.target.value })} />
                <Input placeholder="model_variant" onChange={(e) => setForm({ ...form, model_variant: e.target.value })} />
              </div>
            </details>

            <details>
              <summary className="cursor-pointer font-semibold">Section 8: Sostanze Pericolose</summary>
              <div className="mt-3">
                <Input placeholder="hazardous_substances (comma separated)" onChange={(e) => setForm({ ...form, hazardous_substances: parseTags(e.target.value) })} />
              </div>
            </details>

            <Button className="w-full" size="lg" type="submit">Pubblica DPP On-Chain →</Button>
            <p className="text-xs text-slate-500">Costo: €0.003 (gas blockchain Polygon)</p>
          </form>
        </CardContent>
      </Card>

      <Card className="h-fit">
        <CardHeader><CardTitle>Compliance Live</CardTitle></CardHeader>
        <CardContent>
          <p className="text-sm">{compliance.score}% completo</p>
          <div className="mt-2 h-2 w-full rounded bg-slate-100"><div className="h-2 rounded bg-emerald-500" style={{ width: `${compliance.score}%` }} /></div>
          <p className="mt-3 text-xs text-slate-500">Campi mancanti:</p>
          <ul className="mt-1 space-y-1 text-xs text-amber-700">
            {compliance.missing.length ? compliance.missing.map((field) => <li key={field}>• {field}</li>) : <li>✅ Tutti i campi richiesti compilati</li>}
          </ul>
        </CardContent>
      </Card>
    </div>
  );
}
