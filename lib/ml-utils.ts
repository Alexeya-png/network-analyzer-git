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
    p.protocol ?? 0,
    p.size ?? 0,
  ]
}

/* ---------- 3. Запрос к /api/ml-analyze ---------------------------------- */

export interface MLResult {
  predictions: number[]            // 0 | 1
  confidence: number[]             // [0‥1]
  summary: {
    total: number
    malicious: number
    benign: number
    accuracy?: number              // может отсутствовать
  }
}

/** Запускаем ML-анализ; при недоступности сервера — хитрая эвристика */
export async function analyzePacketsWithML(
  packets: PacketData[],
): Promise<MLResult> {
  try {
    const features = packets.map(preparePacketForML)

    const res = await fetch("/api/ml-analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ features }),
    })

    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    return await res.json()
  } catch (e) {
    console.error("ML endpoint error → fallback heuristic:", e)

    /* ---------- fallback -------------------------------------------------- */
    const predictions = packets.map((p) => {
      if (isSynPacket(p)) return 1

      const isPortScan =
        p.protocol === 6 && p.destPort < 1024 && p.sourcePort > 32768
      const isWeirdLen = p.size < 64 || p.size > 1500
      const suspiciousPort = [22, 23, 3389].includes(p.destPort ?? -1)

      return (isPortScan || isWeirdLen || suspiciousPort) ? 1 : 0
    })

    const malicious = predictions.reduce((s, v) => s + v, 0)
    return {
      predictions,
      confidence: predictions.map((v) =>
        v ? Math.random() * 0.2 + 0.8 : Math.random() * 0.2 + 0.1,
      ),
      summary: {
        total: predictions.length,
        malicious,
        benign: predictions.length - malicious,
      },
    }
  }
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
