"use client"

import type React from "react"

import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Play, Square, Save, Upload, Filter } from "lucide-react"
import type { PacketData } from "@/lib/types"

// Update the interface to include packets
interface PacketCaptureProps {
  isCapturing: boolean
  setIsCapturing: (value: boolean) => void
  onNewPackets: (packets: PacketData[]) => void
  onClearPackets: () => void
  packets: PacketData[] // Add this line
}

// Update the function signature to include packets
export function PacketCapture({
  isCapturing,
  setIsCapturing,
  onNewPackets,
  onClearPackets,
  packets,
}: PacketCaptureProps) {
  const [interface_, setInterface] = useState("")
  const [filter, setFilter] = useState("")
  const [interfaces, setInterfaces] = useState([
    { id: "eth0", name: "Ethernet" },
    { id: "wlan0", name: "Wi-Fi" },
    { id: "lo", name: "Loopback" },
  ])

  const handleStartCapture = async () => {
    if (!interface_) return

    setIsCapturing(true)
    console.log("Starting capture on interface:", interface_)

    // In a real implementation, this would connect to a backend service
    // that uses scapy or a similar library to capture packets
    // For demo purposes, we'll simulate packet capture
    simulatePacketCapture()
  }

  const handleStopCapture = () => {
    setIsCapturing(false)
    console.log("Capture stopped") // Add logging
    // In a real implementation, this would stop the packet capture
  }

  const handleLoadPcap = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return

    // In a real implementation, this would parse the PCAP file
    // For demo purposes, we'll simulate loading packets
    const packets = await simulateLoadPcap(file)
    onNewPackets(packets)
  }

  const simulatePacketCapture = () => {
    // This simulates receiving packets at regular intervals
    const interval = setInterval(() => {
      if (!isCapturing) {
        clearInterval(interval)
        return
      }

      const newPackets = generateRandomPackets(5)
      console.log("Generated new packets:", newPackets.length) // Add logging
      onNewPackets(newPackets)
    }, 1000)

    // Store the interval ID to clear it later
    return interval
  }

  const simulateLoadPcap = async (file: File): Promise<PacketData[]> => {
    // In a real implementation, this would parse the PCAP file
    // For demo purposes, we'll generate random packets
    return new Promise((resolve) => {
      setTimeout(() => {
        resolve(generateRandomPackets(100))
      }, 500)
    })
  }

  // Modify the generateRandomPackets function to create more realistic packets
  const generateRandomPackets = (count: number): PacketData[] => {
    const protocols = [1, 6, 17] // ICMP, TCP, UDP
    const packets: PacketData[] = []
    const commonPorts = [80, 443, 22, 53, 8080, 3389]

    for (let i = 0; i < count; i++) {
      const protocol = protocols[Math.floor(Math.random() * protocols.length)]
      const isSynFlood = protocol === 6 && Math.random() < 0.1 // 10% chance of SYN flood for TCP
      const destPort = commonPorts[Math.floor(Math.random() * commonPorts.length)]

      packets.push({
        id: Date.now() + i,
        timestamp: new Date().toISOString(),
        sourceIp: generateRandomIp(),
        destIp: generateRandomIp(),
        sourcePort: Math.floor(Math.random() * 65535),
        destPort: destPort,
        protocol,
        size: Math.floor(Math.random() * 1500) + 40, // More realistic packet sizes
        flags: protocol === 6 ? (isSynFlood ? "S" : "PA") : "",
        isMalicious: isSynFlood,
        data: Array(Math.floor(Math.random() * 100) + 20)
          .fill(0)
          .map(() =>
            Math.floor(Math.random() * 256)
              .toString(16)
              .padStart(2, "0"),
          )
          .join(" "),
      })
    }

    return packets
  }

  // Add a function to simulate a SYN flood attack
  const simulateSynFlood = (targetIp: string, targetPort: number, count: number): PacketData[] => {
    console.log(`Simulating SYN flood attack to ${targetIp}:${targetPort}, ${count} packets`)
    const packets: PacketData[] = []

    for (let i = 0; i < count; i++) {
      const sourceIp = generateRandomIp() // Random source IP for each packet (IP spoofing)

      packets.push({
        id: Date.now() + i,
        timestamp: new Date().toISOString(),
        sourceIp: sourceIp,
        destIp: targetIp,
        sourcePort: Math.floor(Math.random() * 65535), // Random source port
        destPort: targetPort,
        protocol: 6, // TCP
        size: 40 + Math.floor(Math.random() * 20), // TCP SYN packets are small
        flags: "S", // SYN flag
        isMalicious: true, // Mark as malicious
        data: `45 00 00 28 ${Math.floor(Math.random() * 256)
          .toString(16)
          .padStart(2, "0")} ${Math.floor(Math.random() * 256)
          .toString(16)
          .padStart(2, "0")} 40 00 40 06 00 00 ${sourceIp
          .split(".")
          .map((octet) => Number.parseInt(octet).toString(16).padStart(2, "0"))
          .join(" ")} ${targetIp
          .split(".")
          .map((octet) => Number.parseInt(octet).toString(16).padStart(2, "0"))
          .join(" ")}`,
      })
    }

    return packets
  }

  const generateRandomIp = () => {
    return `${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`
  }

  // Improve the handleSavePackets function to better handle errors and provide feedback
  const handleSavePackets = () => {
    console.log("Save button clicked, packets:", packets.length)

    if (packets.length === 0) {
      console.log("No packets to save")
      alert("No packets to save")
      return
    }

    try {
      // Convert packets to JSON
      const packetData = JSON.stringify(packets, null, 2)

      // Create a blob and download it
      const blob = new Blob([packetData], { type: "application/json" })
      const url = URL.createObjectURL(blob)
      const a = document.createElement("a")
      a.href = url
      a.download = `network_capture_${new Date().toISOString().replace(/[:.]/g, "-")}.json`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)

      console.log(`Saved ${packets.length} packets`)
      alert(`Successfully saved ${packets.length} packets`)
    } catch (error) {
      console.error("Error saving packets:", error)
      alert(`Error saving packets: ${error}`)
    }
  }

  return (
    <div className="p-4 border-b bg-muted/20">
      <div className="flex items-end gap-4">
        <div className="grid w-full max-w-sm items-center gap-1.5">
          <Label htmlFor="interface">Interface</Label>
          <Select value={interface_} onValueChange={setInterface}>
            <SelectTrigger>
              <SelectValue placeholder="Select interface" />
            </SelectTrigger>
            <SelectContent>
              {interfaces.map((iface) => (
                <SelectItem key={iface.id} value={iface.id}>
                  {iface.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        <div className="grid w-full max-w-sm items-center gap-1.5">
          <Label htmlFor="filter">Filter</Label>
          <div className="flex gap-2">
            <Input id="filter" placeholder="tcp port 80" value={filter} onChange={(e) => setFilter(e.target.value)} />
            <Button variant="outline" size="icon">
              <Filter className="h-4 w-4" />
            </Button>
          </div>
        </div>

        <div className="flex gap-2">
          {!isCapturing ? (
            <Button onClick={handleStartCapture} disabled={!interface_}>
              <Play className="h-4 w-4 mr-2" />
              Start
            </Button>
          ) : (
            <Button onClick={handleStopCapture} variant="destructive">
              <Square className="h-4 w-4 mr-2" />
              Stop
            </Button>
          )}

          <Button variant="outline" onClick={onClearPackets}>
            Clear
          </Button>

          <div className="relative">
            <Button variant="outline" asChild>
              <label>
                <Upload className="h-4 w-4 mr-2" />
                Load PCAP
                <Input type="file" accept=".pcap,.pcapng" className="sr-only" onChange={handleLoadPcap} />
              </label>
            </Button>
          </div>

          <Button variant="outline" onClick={handleSavePackets} disabled={packets.length === 0}>
            <Save className="h-4 w-4 mr-2" />
            Save
          </Button>
          <Button
            variant="outline"
            onClick={() => {
              const targetIp = "192.168.1.1" // Default target
              const targetPort = 80 // Default port
              const attackPackets = simulateSynFlood(targetIp, targetPort, 50)
              onNewPackets(attackPackets)
            }}
          >
            <Play className="h-4 w-4 mr-2" />
            SYN Flood
          </Button>
          <Button
            variant="outline"
            onClick={() => {
              const testPackets = generateRandomPackets(10)
              onNewPackets(testPackets)
              console.log("Generated 10 test packets")
            }}
          >
            Test Packets
          </Button>
        </div>
      </div>
    </div>
  )
}
