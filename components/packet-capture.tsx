"use client"

import type React from "react"
import { useState, useRef } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Play, Square, Save, Upload, Filter, Brain } from "lucide-react"
import type { PacketData } from "@/lib/types"
import { parsePcapFile, saveToPcap } from "@/lib/pcap-utils"
import { useToast } from "@/hooks/use-toast"
import { analyzePacketsWithML, isSynPacket } from "@/lib/ml-utils"

interface Packet {
  id: string
  source: string
  destination: string
  protocol: string
  length: number
  info: string
  mlConfidence?: number
  mlPrediction?: string
}

interface MLAnalysisResults {
  confidence: number[]
  predictions: string[]
  summary: {
    total: number
    malicious: number
    accuracy: number
  }
  packetsWithML?: Packet[]
}

interface PacketCaptureProps {
  isCapturing: boolean
  setIsCapturing: (value: boolean) => void
  onNewPackets: (packets: PacketData[]) => void
  onClearPackets: () => void
  packets: PacketData[]
  connectToServer?: (interface_: string, filter: string) => void
  stopCapture?: () => void
  onMLAnalysisComplete?: (results: any) => void
}

export function PacketCapture({
  isCapturing,
  setIsCapturing,
  onNewPackets,
  onClearPackets,
  packets,
  connectToServer,
  stopCapture,
  onMLAnalysisComplete,
}: PacketCaptureProps) {
  const [interface_, setInterface] = useState("")
  const [filter, setFilter] = useState("")
  const [interfaces, setInterfaces] = useState([
    { id: "\\Device\\NPF_Loopback", name: "Loopback" },
    { id: "eth0", name: "Ethernet" },
    { id: "wlan0", name: "Wi-Fi" },
  ])
  const [isLoading, setIsLoading] = useState(false)
  const wsRef = useRef<WebSocket | null>(null)
  const { toast } = useToast()
  const [isAnalyzing, setIsAnalyzing] = useState(false)

  const handleStartCapture = async () => {
    console.log("Starting capture on interface:", interface_ || "default")

    if (connectToServer) {
      connectToServer(interface_ || "\\Device\\NPF_Loopback", filter)
    } else {
      connectToServerWithWebSocket(interface_ || "\\Device\\NPF_Loopback", filter)
    }
  }

  const handleStopCapture = () => {
    console.log("Stopping capture")

    if (stopCapture) {
      stopCapture()
    } else {
      setIsCapturing(false)
    }
  }

  const handleLoadPcap = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return

    setIsLoading(true)
    try {
      if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
        const reader = new FileReader()
        reader.onload = async (event) => {
          if (event.target?.result) {
            const base64Data = (event.target.result as string).split(",")[1]
            wsRef.current?.send(
              JSON.stringify({
                command: "load_pcap",
                pcap_data: base64Data,
              }),
            )
            toast({
              title: "PCAP файл загружен",
              description: `Файл ${file.name} отправлен на сервер для обработки`,
            })
          }
        }
        reader.readAsDataURL(file)
      } else {
        const parsedPackets = await parsePcapFile(file)
        onNewPackets(parsedPackets)
        toast({
          title: "PCAP файл загружен",
          description: `Загружено ${parsedPackets.length} пакетов из файла ${file.name}`,
        })
      }
    } catch (error) {
      console.error("Error loading PCAP file:", error)
      toast({
        title: "Ошибка загрузки PCAP",
        description: `Не удалось загрузить файл: ${error}`,
        variant: "destructive",
      })
    } finally {
      setIsLoading(false)
      e.target.value = ""
    }
  }

  const handleSavePackets = async () => {
    console.log("Save button clicked, packets:", packets.length)

    if (packets.length === 0) {
      toast({
        title: "Нет пакетов для сохранения",
        description: "Захватите сетевой трафик перед сохранением",
        variant: "destructive",
      })
      return
    }

    try {
      const blob = await saveToPcap(packets)
      const url = URL.createObjectURL(blob)
      const a = document.createElement("a")
      a.href = url
      a.download = `network_capture_${new Date().toISOString().replace(/[:.]/g, "-")}.pcap`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)

      toast({
        title: "PCAP файл сохранен",
        description: `Сохранено ${packets.length} пакетов`,
      })
    } catch (error) {
      console.error("Error saving packets to PCAP:", error)
      toast({
        title: "Ошибка сохранения PCAP",
        description: `Не удалось сохранить файл: ${error}`,
        variant: "destructive",
      })
    }
  }

  const handleNewPackets = (newPackets: PacketData[]) => {
    onNewPackets(newPackets)
  }

  const connectToServerWithWebSocket = (interface_: string, filter: string) => {
    if (wsRef.current) {
      wsRef.current.close()
    }

    try {
      console.log("Connecting to WebSocket server...")
      const ws = new WebSocket(`ws://localhost:8000?iface=${interface_}&filter=${filter}`)
      wsRef.current = ws

      ws.onopen = () => {
        console.log("Connected to WebSocket server")
        setIsCapturing(true)
        toast({
          title: "Подключено к серверу",
          description: "WebSocket соединение установлено",
        })
      }

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data)

          if (data.type === "command_response") {
            console.log("Command response received:", data)
            if (data.command === "load_pcap" && data.status === "success") {
              toast({
                title: "PCAP файл загружен",
                description: `Загружено ${data.packet_count} пакетов`,
              })
            } else if (data.command === "save_pcap" && data.status === "success") {
              toast({
                title: "PCAP файл сохранен",
                description: `Файл сохранен как ${data.filename}`,
              })
            }
          } else {
            handleNewPackets([data])
          }
        } catch (error) {
          console.error("Error processing message:", error)
        }
      }

      ws.onclose = () => {
        console.log("Disconnected from WebSocket server")
        setIsCapturing(false)
        toast({
          title: "Соединение закрыто",
          description: "WebSocket соединение с сервером закрыто",
        })
      }

      ws.onerror = (error) => {
        console.error("WebSocket error:", error)
        setIsCapturing(false)
        toast({
          title: "Ошибка соединения",
          description: "Не удалось подключиться к серверу",
          variant: "destructive",
        })
      }
    } catch (error) {
      console.error("Error connecting to Python server:", error)
      setIsCapturing(false)
      toast({
        title: "Ошибка соединения",
        description: `Не удалось подключиться к серверу: ${error}`,
        variant: "destructive",
      })
    }
  }

  const handleMLAnalysis = async () => {
    console.log("ML Analysis button clicked!")
    console.log("Current packets:", packets.length)

    if (packets.length === 0) {
      toast({
        title: "Нет пакетов для анализа",
        description: "Захватите сетевой трафик перед анализом",
        variant: "destructive",
      })
      return
    }

    setIsAnalyzing(true)

    const targetPackets = packets;

    console.log(`Found ${targetPackets.length} SYN packets out of ${packets.length} total packets`)

    toast({
      title: "Начинаем ML анализ",
      description: `Анализируем ${packets.length} пакетов (найдено ${targetPackets.length} SYN пакетов)...`,
    })

    try {
      console.log("Calling analyzePacketsWithML on SYN packets...")
      const result = await analyzePacketsWithML(targetPackets);
      console.log("ML Analysis result:", result)

      const updatedPackets = packets.map((packet) => {
        const idx = targetPackets.indexOf(packet);
        const isMLMalicious = idx >= 0
          ? result.predictions[idx]
          : packet.isMalicious;
        return {
          ...packet,
          isMalicious: isMLMalicious || packet.isMalicious,
          mlPrediction: isMLMalicious,
        };
      })

      console.log("Updated packets with ML results:", updatedPackets.slice(0, 3))

      if (onMLAnalysisComplete) {
        onMLAnalysisComplete(result.summary);
      }

      const synMaliciousCount = updatedPackets.filter((packet) => isSynPacket(packet) && packet.isMalicious).length

      toast({
        title: "ML анализ завершен",
        description: `Обнаружено ${result.summary.malicious} подозрительных пакетов из ${result.summary.total}. SYN пакетов: ${synMaliciousCount}. Точность: ${(result.summary.accuracy * 100).toFixed(1)}%`,
      })
    } catch (error) {
      console.error("Error in ML analysis:", error)
      toast({
        title: "Ошибка ML анализа",
        description: `Не удалось выполнить анализ: ${error}`,
        variant: "destructive",
      })
    } finally {
      setIsAnalyzing(false)
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
            <Button variant="outline" asChild disabled={isLoading}>
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
            onClick={handleMLAnalysis}
            disabled={packets.length === 0 || isAnalyzing}
            className="bg-blue-50 hover:bg-blue-100 border-blue-200"
          >
            <Brain className="h-4 w-4 mr-2" />
            {isAnalyzing ? "Analyzing..." : "ML Analysis"}
          </Button>
        </div>
      </div>
    </div>
  )
}
