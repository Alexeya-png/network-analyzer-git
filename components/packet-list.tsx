"use client"

import { useState } from "react"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Input } from "@/components/ui/input"
import type { PacketData } from "@/lib/types"
import { formatTimestamp, getProtocolName } from "@/lib/utils"
import { cn } from "@/lib/utils"

interface PacketListProps {
  packets: PacketData[]
  selectedPacket: PacketData | null
  setSelectedPacket: (packet: PacketData) => void
}

export function PacketList({ packets, selectedPacket, setSelectedPacket }: PacketListProps) {
  const [searchTerm, setSearchTerm] = useState("")

  const filteredPackets = packets.filter((packet) => {
    if (!searchTerm) return true

    const searchLower = searchTerm.toLowerCase()
    return (
      packet.sourceIp.includes(searchTerm) ||
      packet.destIp.includes(searchTerm) ||
      getProtocolName(packet.protocol).toLowerCase().includes(searchLower) ||
      (packet.data && packet.data.toLowerCase().includes(searchLower))
    )
  })

  // Функция для создания стабильного ключа для каждого пакета
  const getPacketKey = (packet: PacketData, index: number): string => {
    // Всегда используем индекс как основу для уникальности
    const baseKey = `packet-${index}`

    // Добавляем дополнительные характеристики для большей уникальности
    const additionalInfo = `${packet.timestamp}-${packet.sourceIp}-${packet.sourcePort}-${packet.destIp}-${packet.destPort}-${packet.protocol}`

    // Создаем хеш из дополнительной информации для сокращения длины ключа
    const hash = additionalInfo.split("").reduce((a, b) => {
      a = (a << 5) - a + b.charCodeAt(0)
      return a & a
    }, 0)

    return `${baseKey}-${Math.abs(hash)}`
  }

  return (
    <div className="flex flex-col h-full">
      <div className="p-2 border-b">
        <Input
          placeholder="Search packets..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className="max-w-md"
        />
      </div>
      <div className="flex-1 overflow-auto">
        <Table>
          <TableHeader className="sticky top-0 bg-background">
            <TableRow>
              <TableHead className="w-[100px]">No.</TableHead>
              <TableHead className="w-[180px]">Time</TableHead>
              <TableHead className="w-[150px]">Source</TableHead>
              <TableHead className="w-[150px]">Destination</TableHead>
              <TableHead className="w-[100px]">Protocol</TableHead>
              <TableHead className="w-[80px]">Length</TableHead>
              <TableHead>Info</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {filteredPackets.length > 0 ? (
              filteredPackets.map((packet, index) => (
                <TableRow
                  key={getPacketKey(packet, index)}
                  className={cn(
                    `cursor-pointer ${selectedPacket?.id === packet.id ? "bg-muted" : ""}`,
                    packet.isMalicious && packet.protocol === 6 && packet.flags === "S"
                      ? "bg-red-100 hover:bg-red-200 dark:bg-red-900/30 dark:hover:bg-red-900/40 border-l-4 border-l-red-500"
                      : packet.isMalicious
                        ? "bg-red-50 hover:bg-red-100 dark:bg-red-900/20 dark:hover:bg-red-900/30"
                        : "",
                  )}
                  onClick={() => setSelectedPacket(packet)}
                >
                  <TableCell>{index + 1}</TableCell>
                  <TableCell>{formatTimestamp(packet.timestamp)}</TableCell>
                  <TableCell>{`${packet.sourceIp}:${packet.sourcePort}`}</TableCell>
                  <TableCell>{`${packet.destIp}:${packet.destPort}`}</TableCell>
                  <TableCell>{getProtocolName(packet.protocol)}</TableCell>
                  <TableCell>{packet.size}</TableCell>
                  <TableCell>
                    {packet.protocol === 6 && packet.flags ? (
                      <span>
                        {packet.flags === "S" ? (
                          <>
                            <span className="font-medium">SYN</span> {" "}
                            Win=64240
                          </>
                        ) : packet.flags === "PA" ? (
                          "PSH ACK Seq=0 Win=64240"
                        ) : packet.flags === "A" ? (
                          "ACK"
                        ) : (
                          packet.flags
                        )}
                      </span>
                    ) : (
                      "Standard packet"
                    )}
                    {packet.isMalicious && (
                      <span className="ml-2 text-red-600 font-bold dark:text-red-400">
                        [MALICIOUS
                        {packet.destIp === "192.168.1.1" && packet.destPort === 80 ? " - TARGETED ATTACK" : ""}]
                      </span>
                    )}
                  </TableCell>
                </TableRow>
              ))
            ) : (
              <TableRow>
                <TableCell colSpan={7} className="text-center h-32 text-muted-foreground">
                  {packets.length === 0
                    ? "No packets captured. Start capturing or load a PCAP file."
                    : "No packets match your search criteria."}
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </div>
      <div className="p-2 border-t bg-muted/20">
        <p className="text-sm text-muted-foreground">
          {filteredPackets.length} packets displayed
          {packets.length !== filteredPackets.length && ` (filtered from ${packets.length} total)`}
        </p>
      </div>
    </div>
  )
}
