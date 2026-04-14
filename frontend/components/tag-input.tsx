"use client";

import { KeyboardEvent, useState } from "react";
import { X } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";

export function TagInput({ values, onChange, placeholder }: { values: string[]; onChange: (v: string[]) => void; placeholder: string }) {
  const [value, setValue] = useState("");

  function onKeyDown(e: KeyboardEvent<HTMLInputElement>) {
    if (e.key !== "Enter") return;
    e.preventDefault();
    const next = value.trim();
    if (!next || values.includes(next)) return;
    onChange([...values, next]);
    setValue("");
  }

  return (
    <div className="space-y-2">
      <Input placeholder={placeholder} value={value} onChange={(e) => setValue(e.target.value)} onKeyDown={onKeyDown} />
      <div className="flex flex-wrap gap-2">
        {values.map((item) => (
          <Badge key={item} variant="secondary" className="gap-1">
            {item}
            <button type="button" onClick={() => onChange(values.filter((v) => v !== item))}>
              <X className="h-3 w-3" />
            </button>
          </Badge>
        ))}
      </div>
    </div>
  );
}
