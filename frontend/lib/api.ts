// frontend/lib/api.ts - Client for the ProofMint API (backend: proofmint/router.py, prefix /proofmint).
// Brand API key and ID live in the browser's localStorage (keys "hala_*").
// The types below are generated from proofmint/schemas.py (DPPCreate, DPPResponse).

export const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export interface MaterialDetail {
  name: string;
  weight_percent?: number | null;
  recycled_content_percent?: number | null;
  origin_country?: string | null;
}

export interface DPPCreateInput {
  productId: string;
  productName: string;
  category: string;
  materials: string[];
  origin_country: string;
  carbon_footprint_kg?: number | null;
  certifications?: string[];
  recycling_instructions?: string | null;
  brand_name: string;
  materials_detailed?: MaterialDetail[];
  operator_type?: string | null;
  operator_address?: string | null;
  facility_id?: string | null;
  eori_number?: string | null;
  hazardous_substances?: string[];
  reach_compliant?: boolean | null;
  rohs_compliant?: boolean | null;
  carbon_footprint_method?: string | null;
  energy_consumption_kwh?: number | null;
  water_consumption_liters?: number | null;
  expected_lifetime_years?: number | null;
  repair_score?: number | null;
  spare_parts_available?: boolean | null;
  warranty_duration_months?: number | null;
  warranty_terms?: string | null;
  maintenance_instructions?: string | null;
  recyclability_percent?: number | null;
  recycled_content_percent?: number | null;
  disassembly_instructions?: string | null;
  collection_points_url?: string | null;
  reuse_potential?: string | null;
  ce_marking?: boolean | null;
  conformity_declaration_url?: string | null;
  test_reports_urls?: string[];
  hs_code?: string | null;
  cn_code?: string | null;
  product_image_url?: string | null;
  model_variant?: string | null;
}

export interface DPPResponse {
  productId: string;
  productName: string;
  category: string;
  materials: string[];
  origin_country: string;
  carbon_footprint_kg?: number | null;
  certifications: string[];
  recycling_instructions?: string | null;
  brand_name: string;
  materials_detailed?: MaterialDetail[];
  operator_type?: string | null;
  operator_address?: string | null;
  facility_id?: string | null;
  eori_number?: string | null;
  hazardous_substances?: string[];
  reach_compliant?: boolean | null;
  rohs_compliant?: boolean | null;
  carbon_footprint_method?: string | null;
  energy_consumption_kwh?: number | null;
  water_consumption_liters?: number | null;
  expected_lifetime_years?: number | null;
  repair_score?: number | null;
  spare_parts_available?: boolean | null;
  warranty_duration_months?: number | null;
  warranty_terms?: string | null;
  maintenance_instructions?: string | null;
  recyclability_percent?: number | null;
  recycled_content_percent?: number | null;
  disassembly_instructions?: string | null;
  collection_points_url?: string | null;
  reuse_potential?: string | null;
  ce_marking?: boolean | null;
  conformity_declaration_url?: string | null;
  test_reports_urls?: string[];
  hs_code?: string | null;
  cn_code?: string | null;
  product_image_url?: string | null;
  model_variant?: string | null;
  dpp_hash: string;
  blockchain_tx: string;
  ipfs_cid: string;
  created_at: string;
  version: number;
  verification_url: string;
}

export interface BrandRegisterInput {
  name: string;
  email: string;
  plan?: "free" | "pro";
  operator_type?: string;
  address?: string | null;
  country?: string | null;
}

export interface BrandRegisterResponse {
  brand_id: number;
  name: string;
  email: string;
  plan: string;
  api_key: string;
  [key: string]: unknown;
}

export interface ProductInput {
  product_id: string;
  product_name: string;
  category: string;
}

export interface Product {
  id: number;
  product_id: string;
  product_name: string;
  category: string;
  created_at?: string;
  brand_id?: number;
}

export interface BrandStats {
  brand_id: number;
  total_products: number;
  total_scans: number;
  compliance_percent: number;
}

export interface VerifyResult {
  is_valid: boolean;
  passport_data: Record<string, unknown> | null;
}

export type DPPDetail = DPPResponse & { is_active?: boolean; ipfs_payload?: Record<string, unknown> };

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

function apiKey(): string {
  if (typeof window === "undefined") return "";
  return localStorage.getItem("hala_api_key") || "";
}

async function request<T>(path: string, init: RequestInit = {}, auth = true): Promise<T> {
  const headers = new Headers(init.headers);
  if (init.body) headers.set("Content-Type", "application/json");
  if (auth && apiKey()) headers.set("X-API-Key", apiKey());
  const res = await fetch(`${API_BASE}/proofmint${path}`, { ...init, headers, cache: "no-store" });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail ?? body);
    } catch {
      /* body is not JSON */
    }
    throw new ApiError(res.status, detail);
  }
  return res.json() as Promise<T>;
}

export const registerBrand = (input: BrandRegisterInput) =>
  request<BrandRegisterResponse>("/brands/register", { method: "POST", body: JSON.stringify(input) }, false);

export const createProduct = (input: ProductInput) =>
  request<Product>("/products", { method: "POST", body: JSON.stringify(input) });

export const listBrandProducts = (brandId: number) => request<Product[]>(`/brands/${brandId}/products`);

export const getBrandStats = (brandId: number) => request<BrandStats>(`/brands/${brandId}/stats`);

export const createDPP = (input: DPPCreateInput) =>
  request<DPPResponse>("/dpp/create", { method: "POST", body: JSON.stringify(input) });

export const getDPP = (dppId: string | number) => request<DPPDetail>(`/dpp/${dppId}`, {}, false);

export const revokeDPP = (dppId: string | number) =>
  request<{ status: string; dpp_id: number }>(`/dpp/${dppId}`, { method: "DELETE" });

export const verifyProduct = (productId: string) =>
  request<VerifyResult>(`/verify/${encodeURIComponent(productId)}`, {}, false);
