"use client";

import { useMemo, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";

import { TagInput } from "@/components/tag-input";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { createDPP, verifyProduct } from "@/lib/api";
import { useAuth } from "@/lib/auth";

const countries = ["Italy", "France", "Germany", "Spain", "Portugal", "Netherlands", "Other"];

export default function NewDppPage() {
  const { auth } = useAuth();
  const params = useSearchParams();
  const router = useRouter();
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const [form, setForm] = useState({
    productId: params.get("productId") || "",
    productName: params.get("productName") || "",
    category: params.get("category") || "Other",
    model_variant: "",
    product_image_url: "",
    materials: [] as string[],
    materials_detailed: [{ name: "", weight_percent: "", recycled_content_percent: "", origin_country: "" }],
    hazardous_substances: [] as string[],
    reach_compliant: false,
    rohs_compliant: false,
    origin_country: "Italy",
    operator_type: "manufacturer",
    facility_id: "",
    eori_number: "",
    carbon_footprint_kg: "",
    carbon_footprint_method: "Estimated",
    energy_consumption_kwh: "",
    water_consumption_liters: "",
    expected_lifetime_years: "",
    repair_score: "",
    spare_parts_available: false,
    warranty_duration_months: "",
    warranty_terms: "",
    maintenance_instructions: "",
    recycling_instructions: "",
    recyclability_percent: "",
    recycled_content_percent: "",
    disassembly_instructions: "",
    collection_points_url: "",
    reuse_potential: "medium",
    certifications: [] as string[],
    ce_marking: false,
    conformity_declaration_url: "",
    test_reports_urls: [] as string[],
    hs_code: "",
    cn_code: ""
  });

  const requiredValues = [form.productId, form.productName, form.category, form.origin_country, form.recycling_instructions, form.materials.length > 0 ? "ok" : "", auth?.brandName || ""];
  const requiredMissing = [
    !form.productId && "Product ID",
    !form.productName && "Product Name",
    !form.category && "Category",
    !form.origin_country && "Origin Country",
    !form.recycling_instructions && "Recycling Instructions",
    form.materials.length === 0 && "Materials"
  ].filter(Boolean) as string[];

  const recommendedMissing = [
    !form.carbon_footprint_kg && "Carbon Footprint",
    !form.certifications.length && "Certifications",
    !form.recyclability_percent && "Recyclability %",
    !form.expected_lifetime_years && "Expected Lifetime"
  ].filter((item): item is string => Boolean(item));

  const compliance = useMemo(() => {
    const total = 10;
    const filled = [
      ...requiredValues.map((v) => !!v),
      !!form.carbon_footprint_kg,
      form.certifications.length > 0,
      !!form.recyclability_percent,
      !!form.expected_lifetime_years
    ].filter(Boolean).length;
    return Math.round((filled / total) * 100);
  }, [form, requiredValues]);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    if (!auth) return;
    if (requiredMissing.length > 0) return setError("Please fill all required fields.");

    setLoading(true);
    try {
      const payload = {
        productId: form.productId,
        productName: form.productName,
        category: form.category,
        model_variant: form.model_variant || undefined,
        product_image_url: form.product_image_url || undefined,
        materials: form.materials,
        materials_detailed: form.materials_detailed
          .filter((m) => m.name)
          .map((m) => ({
            name: m.name,
            weight_percent: m.weight_percent ? Number(m.weight_percent) : undefined,
            recycled_content_percent: m.recycled_content_percent ? Number(m.recycled_content_percent) : undefined,
            origin_country: m.origin_country || undefined
          })),
        hazardous_substances: form.hazardous_substances,
        reach_compliant: form.reach_compliant,
        rohs_compliant: form.rohs_compliant,
        origin_country: form.origin_country,
        operator_type: form.operator_type,
        facility_id: form.facility_id || undefined,
        eori_number: form.eori_number || undefined,
        carbon_footprint_kg: form.carbon_footprint_kg ? Number(form.carbon_footprint_kg) : undefined,
        carbon_footprint_method: form.carbon_footprint_method,
        energy_consumption_kwh: form.energy_consumption_kwh ? Number(form.energy_consumption_kwh) : undefined,
        water_consumption_liters: form.water_consumption_liters ? Number(form.water_consumption_liters) : undefined,
        expected_lifetime_years: form.expected_lifetime_years ? Number(form.expected_lifetime_years) : undefined,
        repair_score: form.repair_score ? Number(form.repair_score) : undefined,
        spare_parts_available: form.spare_parts_available,
        warranty_duration_months: form.warranty_duration_months ? Number(form.warranty_duration_months) : undefined,
        warranty_terms: form.warranty_terms || undefined,
        maintenance_instructions: form.maintenance_instructions || undefined,
        recycling_instructions: form.recycling_instructions,
        recyclability_percent: form.recyclability_percent ? Number(form.recyclability_percent) : undefined,
        recycled_content_percent: form.recycled_content_percent ? Number(form.recycled_content_percent) : undefined,
        disassembly_instructions: form.disassembly_instructions || undefined,
        collection_points_url: form.collection_points_url || undefined,
        reuse_potential: form.reuse_potential,
        certifications: form.certifications,
        ce_marking: form.ce_marking,
        conformity_declaration_url: form.conformity_declaration_url || undefined,
        test_reports_urls: form.test_reports_urls,
        hs_code: form.hs_code || undefined,
        cn_code: form.cn_code || undefined,
        brand_name: auth.brandName
      };
      await createDPP(payload, auth.apiKey);
      const verify = await verifyProduct(form.productId);
      if (verify.passport_data?.dpp_id) {
        router.push(`/dashboard/dpp/${verify.passport_data.dpp_id}`);
      } else {
        router.push("/dashboard");
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to publish DPP");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="grid gap-6 lg:grid-cols-[1fr_320px]">
      <form className="space-y-4" onSubmit={onSubmit}>
        <details open className="rounded-lg border bg-white p-4"><summary className="cursor-pointer font-semibold">1) Product Identity</summary><div className="mt-4 grid gap-3"><div><Label>Product ID</Label><Input value={form.productId} onChange={(e) => setForm({ ...form, productId: e.target.value })} readOnly={!!params.get("productId")} /></div><div><Label>Product Name</Label><Input value={form.productName} onChange={(e) => setForm({ ...form, productName: e.target.value })} /></div><div><Label>Category</Label><Input value={form.category} onChange={(e) => setForm({ ...form, category: e.target.value })} /></div><div><Label>Model / Variant</Label><Input value={form.model_variant} onChange={(e) => setForm({ ...form, model_variant: e.target.value })} /></div><div><Label>Product Image URL</Label><Input value={form.product_image_url} onChange={(e) => setForm({ ...form, product_image_url: e.target.value })} /></div></div></details>

        <details open className="rounded-lg border bg-white p-4"><summary className="cursor-pointer font-semibold">2) Materials</summary><div className="mt-4 space-y-4"><div><Label>Materials</Label><TagInput values={form.materials} onChange={(materials) => setForm({ ...form, materials })} placeholder="Type material and press Enter" /></div><div><Label>Detailed materials</Label><div className="space-y-2">{form.materials_detailed.map((m, idx) => <div key={idx} className="grid gap-2 sm:grid-cols-4"><Input placeholder="Name" value={m.name} onChange={(e) => setForm((f) => ({ ...f, materials_detailed: f.materials_detailed.map((it, i) => i === idx ? { ...it, name: e.target.value } : it) }))} /><Input placeholder="Weight %" value={m.weight_percent} onChange={(e) => setForm((f) => ({ ...f, materials_detailed: f.materials_detailed.map((it, i) => i === idx ? { ...it, weight_percent: e.target.value } : it) }))} /><Input placeholder="Recycled %" value={m.recycled_content_percent} onChange={(e) => setForm((f) => ({ ...f, materials_detailed: f.materials_detailed.map((it, i) => i === idx ? { ...it, recycled_content_percent: e.target.value } : it) }))} /><Input placeholder="Origin" value={m.origin_country} onChange={(e) => setForm((f) => ({ ...f, materials_detailed: f.materials_detailed.map((it, i) => i === idx ? { ...it, origin_country: e.target.value } : it) }))} /></div>)}</div><Button type="button" variant="outline" onClick={() => setForm({ ...form, materials_detailed: [...form.materials_detailed, { name: "", weight_percent: "", recycled_content_percent: "", origin_country: "" }] })}>Add row</Button></div><div><Label>Hazardous substances</Label><TagInput values={form.hazardous_substances} onChange={(hazardous_substances) => setForm({ ...form, hazardous_substances })} placeholder="Type and press Enter" /></div><div className="flex gap-4 text-sm"><label><input type="checkbox" checked={form.reach_compliant} onChange={(e) => setForm({ ...form, reach_compliant: e.target.checked })} /> REACH compliant</label><label><input type="checkbox" checked={form.rohs_compliant} onChange={(e) => setForm({ ...form, rohs_compliant: e.target.checked })} /> RoHS compliant</label></div></div></details>

        <details open className="rounded-lg border bg-white p-4"><summary className="cursor-pointer font-semibold">3) Origin & Operator</summary><div className="mt-4 grid gap-3"><div><Label>Origin country</Label><Select value={form.origin_country} onValueChange={(origin_country) => setForm({ ...form, origin_country })}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent>{countries.map((c) => <SelectItem key={c} value={c}>{c}</SelectItem>)}</SelectContent></Select></div><div><Label>Operator type</Label><Select value={form.operator_type} onValueChange={(operator_type) => setForm({ ...form, operator_type })}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="manufacturer">manufacturer</SelectItem><SelectItem value="importer">importer</SelectItem><SelectItem value="representative">representative</SelectItem></SelectContent></Select></div><div><Label>Facility ID</Label><Input value={form.facility_id} onChange={(e) => setForm({ ...form, facility_id: e.target.value })} /></div>{form.operator_type === "importer" && <div><Label>EORI number</Label><Input value={form.eori_number} onChange={(e) => setForm({ ...form, eori_number: e.target.value })} /></div>}</div></details>

        <details className="rounded-lg border bg-white p-4"><summary className="cursor-pointer font-semibold">4) Environmental Impact</summary><div className="mt-4 grid gap-3"><div><Label>Carbon footprint (kg CO₂)</Label><div className="flex gap-2"><Input value={form.carbon_footprint_kg} onChange={(e) => setForm({ ...form, carbon_footprint_kg: e.target.value })} /><Button type="button" variant="outline" disabled>Estimate with AI</Button></div><p className="text-xs text-slate-500">AI estimation coming soon.</p></div><div><Label>Method</Label><Select value={form.carbon_footprint_method} onValueChange={(carbon_footprint_method) => setForm({ ...form, carbon_footprint_method })}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent>{["PEF", "ISO 14067", "GHG Protocol", "Estimated"].map((m) => <SelectItem key={m} value={m}>{m}</SelectItem>)}</SelectContent></Select></div><div><Label>Energy (kWh)</Label><Input value={form.energy_consumption_kwh} onChange={(e) => setForm({ ...form, energy_consumption_kwh: e.target.value })} /></div><div><Label>Water (liters)</Label><Input value={form.water_consumption_liters} onChange={(e) => setForm({ ...form, water_consumption_liters: e.target.value })} /></div></div></details>

        <details className="rounded-lg border bg-white p-4"><summary className="cursor-pointer font-semibold">5) Durability & Warranty</summary><div className="mt-4 grid gap-3"><Input placeholder="Expected lifetime years" value={form.expected_lifetime_years} onChange={(e) => setForm({ ...form, expected_lifetime_years: e.target.value })} /><Input placeholder="Repair score 0-10" value={form.repair_score} onChange={(e) => setForm({ ...form, repair_score: e.target.value })} /><label><input type="checkbox" checked={form.spare_parts_available} onChange={(e) => setForm({ ...form, spare_parts_available: e.target.checked })} /> Spare parts available</label><Input placeholder="Warranty months" value={form.warranty_duration_months} onChange={(e) => setForm({ ...form, warranty_duration_months: e.target.value })} /><Textarea placeholder="Warranty terms" value={form.warranty_terms} onChange={(e) => setForm({ ...form, warranty_terms: e.target.value })} /><Textarea placeholder="Maintenance instructions" value={form.maintenance_instructions} onChange={(e) => setForm({ ...form, maintenance_instructions: e.target.value })} /></div></details>

        <details open className="rounded-lg border bg-white p-4"><summary className="cursor-pointer font-semibold">6) Circularity & End of Life</summary><div className="mt-4 grid gap-3"><Textarea required placeholder="Recycling instructions" value={form.recycling_instructions} onChange={(e) => setForm({ ...form, recycling_instructions: e.target.value })} /><Input placeholder="Recyclability %" value={form.recyclability_percent} onChange={(e) => setForm({ ...form, recyclability_percent: e.target.value })} /><Input placeholder="Recycled content %" value={form.recycled_content_percent} onChange={(e) => setForm({ ...form, recycled_content_percent: e.target.value })} /><Textarea placeholder="Disassembly instructions" value={form.disassembly_instructions} onChange={(e) => setForm({ ...form, disassembly_instructions: e.target.value })} /><Input placeholder="Collection points URL" value={form.collection_points_url} onChange={(e) => setForm({ ...form, collection_points_url: e.target.value })} /><Select value={form.reuse_potential} onValueChange={(reuse_potential) => setForm({ ...form, reuse_potential })}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent>{["high", "medium", "low", "none"].map((v) => <SelectItem key={v} value={v}>{v}</SelectItem>)}</SelectContent></Select></div></details>

        <details className="rounded-lg border bg-white p-4"><summary className="cursor-pointer font-semibold">7) Certifications & Conformity</summary><div className="mt-4 grid gap-3"><TagInput values={form.certifications} onChange={(certifications) => setForm({ ...form, certifications })} placeholder="Type cert and press Enter" /><label><input type="checkbox" checked={form.ce_marking} onChange={(e) => setForm({ ...form, ce_marking: e.target.checked })} /> CE marking</label><Input placeholder="Conformity declaration URL" value={form.conformity_declaration_url} onChange={(e) => setForm({ ...form, conformity_declaration_url: e.target.value })} /><TagInput values={form.test_reports_urls} onChange={(test_reports_urls) => setForm({ ...form, test_reports_urls })} placeholder="Type test report URL and press Enter" /></div></details>

        {form.operator_type === "importer" && <details className="rounded-lg border bg-white p-4"><summary className="cursor-pointer font-semibold">8) Customs & Trade</summary><div className="mt-4 grid gap-3"><Input placeholder="HS Code" value={form.hs_code} onChange={(e) => setForm({ ...form, hs_code: e.target.value })} /><Input placeholder="CN Code" value={form.cn_code} onChange={(e) => setForm({ ...form, cn_code: e.target.value })} /></div></details>}

        {error && <p className="text-sm text-red-600">{error}</p>}
        <Button disabled={loading}>{loading ? "Publishing..." : "Publish DPP On-Chain →"}</Button>
        <p className="text-xs text-slate-500">Blockchain registration: ~€0.003</p>
      </form>

      <Card className="h-fit lg:sticky lg:top-6">
        <CardHeader><CardTitle>Compliance</CardTitle></CardHeader>
        <CardContent className="space-y-3 text-sm">
          <p className={`text-2xl font-bold ${compliance < 50 ? "text-red-600" : compliance < 70 ? "text-orange-500" : compliance < 85 ? "text-yellow-500" : "text-green-600"}`}>{compliance}%</p>
          <div>
            <p className="font-semibold">Missing required</p>
            <ul className="list-inside list-disc text-red-600">{requiredMissing.length ? requiredMissing.map((item) => <li key={item}>{item}</li>) : <li className="text-green-700">None</li>}</ul>
          </div>
          <div>
            <p className="font-semibold">Missing recommended</p>
            <ul className="list-inside list-disc text-amber-600">{recommendedMissing.map((item) => <li key={item}>{item}</li>)}</ul>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
