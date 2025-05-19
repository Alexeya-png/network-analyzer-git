"use client"

import { useState } from "react"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { PacketCapture } from "@/components/packet-capture"
import { PacketList } from "@/components/packet-list"
import { PacketDetails } from "@/components/packet-details"
import { AnalysisPanel } from "@/components/analysis-panel"
import type { PacketData } from "@/lib/types"

export function Dashboard() {
  const [packets, setPackets] = useState<PacketData[]>([])
  const [selectedPacket, setSelectedPacket] = useState<PacketData | null>(null)
  const [isCapturing, setIsCapturing] = useState(false)
  const [captureStats, setCaptureStats] = useState({
    total: 0,
    malicious: 0,
    tcp: 0,
    udp: 0,
    icmp: 0,
    other: 0,
  })

  const handleNewPackets = (newPackets: PacketData[]) => {
    console.log("Received new packets:", newPackets.length)

    setPackets((prev) => [...prev, ...newPackets])

    // Update stats
    const stats = { ...captureStats }
    stats.total += newPackets.length

    newPackets.forEach((packet) => {
      if (packet.isMalicious) stats.malicious++

      switch (packet.protocol) {
        case 6: // TCP
          stats.tcp++
          break
        case 17: // UDP
          stats.udp++
          break
        case 1: // ICMP
          stats.icmp++
          break
        default:
          stats.other++
      }
    })

    setCaptureStats(stats)
  }

  const handleClearPackets = () => {
    setPackets([])
    setSelectedPacket(null)
    setCaptureStats({
      total: 0,
      malicious: 0,
      tcp: 0,
      udp: 0,
      icmp: 0,
      other: 0,
    })
  }

  return (
    <div className="flex flex-col h-[calc(100vh-57px)]">
      <div className="flex-none">
        <PacketCapture
          isCapturing={isCapturing}
          setIsCapturing={setIsCapturing}
          onNewPackets={handleNewPackets}
          onClearPackets={handleClearPackets}
          packets={packets} // Add this line
        />
      </div>
      <div className="flex flex-1 overflow-hidden">
        <div className="w-2/3 flex flex-col border-r">
          <PacketList packets={packets} selectedPacket={selectedPacket} setSelectedPacket={setSelectedPacket} />
        </div>
        <div className="w-1/3 flex flex-col">
          <Tabs defaultValue="details">
            <TabsList className="w-full justify-start">
              <TabsTrigger value="details">Packet Details</TabsTrigger>
              <TabsTrigger value="analysis">Analysis</TabsTrigger>
            </TabsList>
            <TabsContent value="details" className="flex-1 overflow-auto p-4">
              {selectedPacket ? (
                <PacketDetails packet={selectedPacket} />
              ) : (
                <div className="text-center text-muted-foreground p-4">Select a packet to view details</div>
              )}
            </TabsContent>
            <TabsContent value="analysis" className="flex-1 overflow-auto">
              <AnalysisPanel stats={captureStats} packets={packets} />
            </TabsContent>
          </Tabs>
        </div>
      </div>
    </div>
  )
}
