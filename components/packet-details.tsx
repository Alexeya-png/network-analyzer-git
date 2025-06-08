"use client"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import type { PacketData } from "@/lib/types"
import { getProtocolName } from "@/lib/utils"

interface PacketDetailsProps {
  packet: PacketData
}

export function PacketDetails({ packet }: PacketDetailsProps) {
  return (
    <Tabs defaultValue="details">
      <TabsList className="w-full justify-start">
        <TabsTrigger value="details">Details</TabsTrigger>
        <TabsTrigger value="hex">Hex</TabsTrigger>
      </TabsList>
      <TabsContent value="details" className="space-y-4">
        <div className="space-y-2">
          <h3 className="font-semibold">Frame</h3>
          <div className="pl-4 space-y-1 text-sm">
            <p>Arrival Time: {new Date(packet.timestamp).toLocaleString()}</p>
            <p>Frame Length: {packet.size} bytes</p>
          </div>
        </div>

        <div className="space-y-2">
          <h3 className="font-semibold">Internet Protocol (IP)</h3>
          <div className="pl-4 space-y-1 text-sm">
            <p>Source Address: {packet.sourceIp}</p>
            <p>Destination Address: {packet.destIp}</p>
            <p>
              Protocol: {getProtocolName(packet.protocol)} ({packet.protocol})
            </p>
          </div>
        </div>

        {packet.protocol === 6 && (
          <div className="space-y-2">
            <h3 className="font-semibold">Transmission Control Protocol (TCP)</h3>
            <div className="pl-4 space-y-1 text-sm">
              <p>Source Port: {packet.sourcePort}</p>
              <p>Destination Port: {packet.destPort}</p>
              <p>Flags: {packet.flags === "S" ? "SYN" : packet.flags === "PA" ? "PSH ACK" : packet.flags}</p>
              {packet.flags === "S" && <p>Sequence Number: {Math.floor(Math.random() * 4294967295)}</p>}
              {packet.isMalicious && (
                <div className="mt-2 p-2 bg-red-100 border border-red-300 rounded-md text-red-800 dark:bg-red-900/20 dark:border-red-800 dark:text-red-400">
                  <p className="font-bold">⚠️ Potential SYN Flood Attack Detected</p>
                  <p className="text-sm mt-1">
                    This packet appears to be part of a SYN flood attack. The source IP may be spoofed.
                    {packet.destIp === "192.168.1.1" && packet.destPort === 80 && (
                      <span className="block mt-1">
                        Matches pattern from known attack script targeting web servers.
                      </span>
                    )}
                  </p>
                </div>
              )}
            </div>
          </div>
        )}

        {packet.protocol === 17 && (
          <div className="space-y-2">
            <h3 className="font-semibold">User Datagram Protocol (UDP)</h3>
            <div className="pl-4 space-y-1 text-sm">
              <p>Source Port: {packet.sourcePort}</p>
              <p>Destination Port: {packet.destPort}</p>
              <p>Length: {packet.size - 28} bytes</p>
            </div>
          </div>
        )}

        {packet.protocol === 1 && (
          <div className="space-y-2">
            <h3 className="font-semibold">Internet Control Message Protocol (ICMP)</h3>
            <div className="pl-4 space-y-1 text-sm">
              <p>Type: Echo Request</p>
              <p>Code: 0</p>
            </div>
          </div>
        )}
      </TabsContent>
      <TabsContent value="hex">
        <div className="font-mono text-xs whitespace-pre-wrap p-4 bg-muted rounded-md overflow-auto max-h-[500px]">
          {formatHexDump(packet.data)}
        </div>
      </TabsContent>
    </Tabs>
  )
}

function formatHexDump(hexData: string) {
  const bytes = hexData.split(" ")
  let result = ""

  for (let i = 0; i < bytes.length; i += 16) {
    const chunk = bytes.slice(i, i + 16)
    const offset = i.toString(16).padStart(8, "0")
    const hexPart = chunk.join(" ").padEnd(48, " ")

    const asciiPart = chunk
      .map((byte) => {
        const code = Number.parseInt(byte, 16)
        return code >= 32 && code <= 126 ? String.fromCharCode(code) : "."
      })
      .join("")

    result += `${offset}  ${hexPart}  |${asciiPart.padEnd(16, " ")}|\n`
  }

  return result
}
