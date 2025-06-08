import type { PacketData } from "./types"

// Константы для PCAP формата
const PCAP_MAGIC_NUMBER = 0xa1b2c3d4 // Magic number для PCAP файла
const PCAP_VERSION_MAJOR = 2 // Версия PCAP формата
const PCAP_VERSION_MINOR = 4
const PCAP_TIMEZONE = 0 // GMT to local correction
const PCAP_SIGFIGS = 0 // Accuracy of timestamps
const PCAP_SNAPLEN = 65535 // Max length of captured packets
const PCAP_NETWORK = 1 // Data link type (1 = Ethernet)

// Функция для парсинга PCAP файла
export async function parsePcapFile(file: File): Promise<PacketData[]> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()

    reader.onload = (event) => {
      try {
        const buffer = event.target?.result as ArrayBuffer
        if (!buffer) {
          reject(new Error("Failed to read file"))
          return
        }

        const packets = parsePcapBuffer(buffer)
        resolve(packets)
      } catch (error) {
        console.error("Error parsing PCAP file:", error)
        reject(error)
      }
    }

    reader.onerror = () => {
      reject(new Error("Failed to read the file"))
    }

    reader.readAsArrayBuffer(file)
  })
}

function parsePcapBuffer(buffer: ArrayBuffer): PacketData[] {
  const dataView = new DataView(buffer)
  const packets: PacketData[] = []

  const magicBE = dataView.getUint32(0, false)
  const magicLE = dataView.getUint32(0, true)

  let littleEndian: boolean

  if (magicBE === 0xa1b2c3d4 || magicBE === 0xa1b23c4d) {
    littleEndian = false
  } else if (magicLE === 0xa1b2c3d4 || magicLE === 0xa1b23c4d) {
    littleEndian = true
  } else {
    throw new Error("Invalid PCAP file format")
  }

  let offset = 24

  while (offset < buffer.byteLength) {
    try {
      const timestampSeconds = dataView.getUint32(offset, littleEndian)
      const timestampMicroseconds = dataView.getUint32(offset + 4, littleEndian)
      const capturedLength = dataView.getUint32(offset + 8, littleEndian)
      const originalLength = dataView.getUint32(offset + 12, littleEndian)

      offset += 16

      if (offset + capturedLength > buffer.byteLength) break

      const packetData = new Uint8Array(buffer.slice(offset, offset + capturedLength))
      const hexData = Array.from(packetData)
        .map((byte) => byte.toString(16).padStart(2, "0"))
        .join(" ")

      const packet = extractPacketInfo(packetData, hexData, timestampSeconds, timestampMicroseconds)
      packets.push(packet)

      offset += capturedLength
    } catch (error) {
      console.error("Error parsing packet:", error)
      offset += 16
    }
  }

  return packets
}

// Функция для извлечения информации о пакете
function extractPacketInfo(
  packetData: Uint8Array,
  hexData: string,
  timestampSeconds: number,
  timestampMicroseconds: number,
): PacketData {
  // Создаем временную метку
  const timestamp = new Date(timestampSeconds * 1000 + timestampMicroseconds / 1000).toISOString()

  // Извлекаем IP заголовок (начинается с 14 байта в Ethernet фрейме)
  const ipHeaderStart = 14

  // Проверяем, что у нас достаточно данных для IP заголовка
  if (packetData.length < ipHeaderStart + 20) {
    // Если недостаточно данных, возвращаем пакет с минимальной информацией
    return {
      id: `packet-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`,
      timestamp,
      sourceIp: "0.0.0.0",
      destIp: "0.0.0.0",
      sourcePort: 0,
      destPort: 0,
      protocol: 0,
      size: packetData.length,
      flags: "",
      isMalicious: false,
      data: hexData,
    }
  }

  // Проверяем версию IP (должна быть 4 для IPv4)
  const ipVersion = (packetData[ipHeaderStart] >> 4) & 0xf
  if (ipVersion !== 4) {
    // Если не IPv4, возвращаем пакет с минимальной информацией
    return {
      id: `packet-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`,
      timestamp,
      sourceIp: "0.0.0.0",
      destIp: "0.0.0.0",
      sourcePort: 0,
      destPort: 0,
      protocol: 0,
      size: packetData.length,
      flags: "",
      isMalicious: false,
      data: hexData,
    }
  }

  // Извлекаем длину IP заголовка
  const ipHeaderLength = (packetData[ipHeaderStart] & 0xf) * 4

  // Извлекаем протокол
  const protocol = packetData[ipHeaderStart + 9]

  // Извлекаем IP адреса
  const sourceIp = `${packetData[ipHeaderStart + 12]}.${packetData[ipHeaderStart + 13]}.${packetData[ipHeaderStart + 14]}.${packetData[ipHeaderStart + 15]}`
  const destIp = `${packetData[ipHeaderStart + 16]}.${packetData[ipHeaderStart + 17]}.${packetData[ipHeaderStart + 18]}.${packetData[ipHeaderStart + 19]}`

  // Начало транспортного заголовка
  const transportHeaderStart = ipHeaderStart + ipHeaderLength

  // Проверяем, что у нас достаточно данных для транспортного заголовка
  if (packetData.length < transportHeaderStart + 4) {
    // Если недостаточно данных, возвращаем пакет с IP информацией, но без портов
    return {
      id: `packet-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`,
      timestamp,
      sourceIp,
      destIp,
      sourcePort: 0,
      destPort: 0,
      protocol,
      size: packetData.length,
      flags: "",
      isMalicious: false,
      data: hexData,
    }
  }

  // Извлекаем порты (для TCP и UDP)
  const sourcePort = (packetData[transportHeaderStart] << 8) | packetData[transportHeaderStart + 1]
  const destPort = (packetData[transportHeaderStart + 2] << 8) | packetData[transportHeaderStart + 3]

  // Извлекаем флаги TCP (если это TCP пакет)
  let flags = ""
  let isMalicious = false

  if (protocol === 6) {
    // TCP
    // Проверяем, что у нас достаточно данных для TCP заголовка
    if (packetData.length >= transportHeaderStart + 14) {
      const tcpFlags = packetData[transportHeaderStart + 13]

      // Извлекаем флаги TCP
      if (tcpFlags & 0x02) flags += "S" // SYN
      if (tcpFlags & 0x10) flags += "A" // ACK
      if (tcpFlags & 0x08) flags += "P" // PSH
      if (tcpFlags & 0x01) flags += "F" // FIN
      if (tcpFlags & 0x04) flags += "R" // RST
      if (tcpFlags & 0x20) flags += "U" // URG

      // Проверяем на SYN флуд (SYN пакет на порт 80)
      isMalicious = (tcpFlags & 0x02) > 0 && destPort === 80
    }
  }

  return {
    id: `packet-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`,
    timestamp,
    sourceIp,
    destIp,
    sourcePort,
    destPort,
    protocol,
    size: packetData.length,
    flags,
    isMalicious,
    data: hexData,
  }
}

// Функция для сохранения пакетов в PCAP формат
export async function saveToPcap(packets: PacketData[]): Promise<Blob> {
  // Рассчитываем размер буфера
  let totalSize = 24 // Глобальный заголовок

  // Добавляем размер для каждого пакета
  packets.forEach((packet) => {
    // Заголовок пакета (16 байт) + данные пакета
    const dataBytes = packet.data ? packet.data.split(" ").length : 0
    totalSize += 16 + dataBytes
  })

  // Создаем буфер для PCAP файла
  const buffer = new ArrayBuffer(totalSize)
  const dataView = new DataView(buffer)

  // Записываем глобальный заголовок PCAP
  dataView.setUint32(0, PCAP_MAGIC_NUMBER, false) // Magic number
  dataView.setUint16(4, PCAP_VERSION_MAJOR, false) // Major version
  dataView.setUint16(6, PCAP_VERSION_MINOR, false) // Minor version
  dataView.setInt32(8, PCAP_TIMEZONE, false) // GMT to local correction
  dataView.setUint32(12, PCAP_SIGFIGS, false) // Accuracy of timestamps
  dataView.setUint32(16, PCAP_SNAPLEN, false) // Max length of captured packets
  dataView.setUint32(20, PCAP_NETWORK, false) // Data link type

  // Текущая позиция в буфере
  let offset = 24

  // Записываем каждый пакет
  packets.forEach((packet) => {
    // Преобразуем timestamp в секунды и микросекунды
    const timestamp = new Date(packet.timestamp).getTime() / 1000
    const timestampSeconds = Math.floor(timestamp)
    const timestampMicroseconds = Math.floor((timestamp - timestampSeconds) * 1000000)

    // Парсим данные пакета
    const dataBytes = packet.data ? packet.data.split(" ").map((hex) => Number.parseInt(hex, 16)) : []
    const packetLength = dataBytes.length

    // Записываем заголовок пакета
    dataView.setUint32(offset, timestampSeconds, false) // Timestamp seconds
    dataView.setUint32(offset + 4, timestampMicroseconds, false) // Timestamp microseconds
    dataView.setUint32(offset + 8, packetLength, false) // Captured packet length
    dataView.setUint32(offset + 12, packet.size || packetLength, false) // Original packet length

    // Смещаем указатель
    offset += 16

    // Записываем данные пакета
    for (let i = 0; i < dataBytes.length; i++) {
      dataView.setUint8(offset + i, dataBytes[i])
    }

    // Смещаем указатель
    offset += packetLength
  })

  // Создаем Blob из буфера
  return new Blob([buffer], { type: "application/vnd.tcpdump.pcap" })
}
