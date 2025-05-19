import { type ClassValue, clsx } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function formatTimestamp(timestamp: string) {
  const date = new Date(timestamp)
  return date.toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    fractionalSecondDigits: 3,
  })
}

export function getProtocolName(protocol: number) {
  switch (protocol) {
    case 1:
      return "ICMP"
    case 6:
      return "TCP"
    case 17:
      return "UDP"
    default:
      return `Protocol ${protocol}`
  }
}

export function ipToInt(ip: string) {
  try {
    const parts = ip.split(".")
    return (
      ((Number.parseInt(parts[0], 10) << 24) |
        (Number.parseInt(parts[1], 10) << 16) |
        (Number.parseInt(parts[2], 10) << 8) |
        Number.parseInt(parts[3], 10)) >>>
      0
    )
  } catch (e) {
    return 0
  }
}
