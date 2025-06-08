import { type ClassValue, clsx } from "clsx"
import { twMerge } from "tailwind-merge"
import type { PacketData } from "./types"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

// Улучшим функцию formatTimestamp для корректной работы с разными форматами timestamp
export function formatTimestamp(timestamp: string | number) {
  let date: Date

  if (typeof timestamp === "number") {
    // Если timestamp - число, предполагаем, что это Unix timestamp в секундах
    date = new Date(timestamp * 1000)
  } else if (typeof timestamp === "string") {
    // Если timestamp - строка, пробуем преобразовать в Date
    if (timestamp.match(/^\d+(\.\d+)?$/)) {
      // Если строка содержит только цифры, считаем её Unix timestamp
      date = new Date(Number.parseFloat(timestamp) * 1000)
    } else {
      // Иначе пробуем парсить как ISO строку
      date = new Date(timestamp)
    }
  } else {
    // Если ничего не подходит, используем текущее время
    date = new Date()
  }

  // Проверяем валидность даты
  if (isNaN(date.getTime())) {
    console.warn(`Invalid timestamp: ${timestamp}, using current time instead`)
    date = new Date()
  }

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

// Улучшенная функция для обнаружения SYN-флуд атак
export function detectSynFlood(packets: PacketData[]): boolean {
  // Берем последние 100 пакетов для анализа
  const recentPackets = packets.slice(-100)

  // Если пакетов слишком мало, не считаем это атакой
  if (recentPackets.length < 10) {
    return false
  }

  // Подсчитываем SYN-пакеты
  const synPackets = recentPackets.filter((p) => p.protocol === 6 && p.flags === "S")

  // Если более 30% пакетов - SYN, это может быть флуд
  if (synPackets.length / recentPackets.length > 0.3) {
    return true
  }

  // Анализируем источники SYN-пакетов
  const destinations = new Map<string, Set<string>>()

  for (const packet of synPackets) {
    if (!destinations.has(packet.destIp)) {
      destinations.set(packet.destIp, new Set())
    }
    destinations.get(packet.destIp)?.add(packet.sourceIp)
  }

  // Если какой-то IP получает SYN-пакеты от многих разных источников, это признак атаки
  for (const [destIp, sources] of destinations.entries()) {
    // Если более 5 разных источников отправляют SYN-пакеты на один IP
    if (sources.size > 5 && synPackets.length > 10) {
      return true
    }
  }

  // Проверяем на признаки Python-скрипта SYN-флуда
  // Ищем пакеты, направленные на порт 80 с флагом SYN
  const synToPort80 = synPackets.filter((p) => p.destPort === 80)
  if (synToPort80.length > 3) {
    // Если есть несколько SYN-пакетов на порт 80, это может быть атака
    return true
  }

  return false
}
