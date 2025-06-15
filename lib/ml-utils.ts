import type { PacketData } from "./types"

/* ---------- 1. Утилиты ---------------------------------------------------- */

/** IPv4 → uint32  (0 при любой ошибке) */
export function ipToInt(addr: string): number {
  const p = addr.split(".")
  if (p.length !== 4) return 0
  return (
    ((+p[0] << 24) | (+p[1] << 16) | (+p[2] << 8) | +p[3]) >>> 0 // unsigned
  )
}

/** true → TCP SYN */
export function isSynPacket(p: PacketData): boolean {
  return p.protocol === 6 && p.flags === "S"
}

/* ---------- 2. Фичи для Random Forest ------------------------------------ */

/**
 * Порядок и состав строго совпадают с train_model.py:
 *   [src_ip, dst_ip, proto, length]
 */
export function preparePacketForML(p: PacketData): number[] {
  return [
    ipToInt(p.sourceIp),
    ipToInt(p.destIp),
    p.sourcePort ?? 0,
    p.destPort   ?? 0,
    p.protocol   ?? 0,
    p.size       ?? 0,
  ];
}

/* ---------- 3. Запрос к /api/ml-analyze ---------------------------------- */

// lib/ml-utils.ts
export async function analyzePacketsWithML(
  packets: PacketData[],
): Promise<MLResult> {
  const features = packets.map(preparePacketForML);

  const res = await fetch('/api/ml-analyze', {
    method: 'POST',
    cache: 'no-store',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ features }),
  });

  const text = await res.text();
  if (!res.ok) {
    // теперь выкидываем вместе со всем телом ответа (где лежит stderr)
    throw new Error(`ML API HTTP ${res.status}: ${text}`);
  }
  return JSON.parse(text);
}

/* ---------- 4. Экспорт в CSV для переобучения ----------------------------- */

export function packetsToCSV(packets: PacketData[]): string {
  const header = ["src_ip", "dst_ip", "proto", "length", "label"].join(",")

  const rows = packets.map((p) => {
    const [sIP, dIP, proto, len] = preparePacketForML(p)
    const label = p.isMalicious ? 1 : 0
    return [sIP, dIP, proto, len, label].join(",")
  })

  return [header, ...rows].join("\n")
}
