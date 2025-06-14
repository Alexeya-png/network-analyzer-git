"use client"

import { useState, useEffect, useRef, useCallback } from "react"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { PacketCapture } from "@/components/packet-capture"
import { PacketList } from "@/components/packet-list"
import { PacketDetails } from "@/components/packet-details"
import { AnalysisPanel } from "@/components/analysis-panel"
import type { PacketData } from "@/lib/types"
import { detectSynFlood } from "@/lib/utils"
import { useToast } from "@/hooks/use-toast"

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
  const [mlAnalysisResults, setMLAnalysisResults] = useState<any>(null)

  // WebSocket ref
  const wsRef = useRef<WebSocket | null>(null)
  const { toast } = useToast()

  // Используем Set для отслеживания уже полученных пакетов
  // Но теперь будем хранить только хеши пакетов, а не сами пакеты
  const processedPacketsRef = useRef(new Set<string>())

  // Функция для создания хеша пакета на основе его ключевых характеристик
  const getPacketHash = useCallback((packet: PacketData): string => {
    // Для SYN-пакетов используем более специфичный хеш, чтобы не пропустить атаку
    if (packet.protocol === 6 && packet.flags === "S") {
      // Для SYN-пакетов важно учитывать только IP-адреса и порты,
      // но не timestamp, так как он может быть очень близким
      return `syn-${packet.sourceIp}-${packet.sourcePort}-${packet.destIp}-${packet.destPort}`
    }

    // Для остальных пакетов используем более полный хеш
    return `${packet.timestamp}-${packet.sourceIp}-${packet.sourcePort}-${packet.destIp}-${packet.destPort}-${packet.protocol}-${packet.size}`
  }, [])

  // Улучшим функцию handleNewPackets для более надежной обработки пакетов
  const handleNewPackets = useCallback(
    (newPackets: PacketData[]) => {
      if (!newPackets || newPackets.length === 0) {
        console.log("Получен пустой массив пакетов")
        return
      }

      console.log(`Получено ${newPackets.length} пакетов для обработки`)

      // Фильтруем только уникальные пакеты
      const uniquePackets = newPackets.filter((packet) => {
        if (!packet || !packet.sourceIp) {
          console.warn("Получен некорректный пакет:", packet)
          return false
        }

        const packetHash = getPacketHash(packet)

        // Если это SYN-пакет, мы хотим пропускать его, только если он точно дубликат
        // и был получен недавно (в течение последних 10 секунд)
        if (packet.protocol === 6 && packet.flags === "S") {
          // Для SYN-пакетов мы добавляем временную метку к хешу
          // и удаляем старые хеши через некоторое время
          const timeBasedHash = `${packetHash}-${Math.floor(Date.now() / 10000)}` // Группируем по 10-секундным интервалам

          if (processedPacketsRef.current.has(timeBasedHash)) {
            return false
          }

          processedPacketsRef.current.add(timeBasedHash)

          // Очищаем старые хеши SYN-пакетов, чтобы не переполнять память
          setTimeout(() => {
            processedPacketsRef.current.delete(timeBasedHash)
          }, 30000) // Удаляем через 30 секунд

          return true
        }

        // Для обычных пакетов используем стандартную дедупликацию
        if (processedPacketsRef.current.has(packetHash)) {
          return false
        }

        processedPacketsRef.current.add(packetHash)
        return true
      })

      if (uniquePackets.length === 0) {
        console.log("Нет новых уникальных пакетов")
        return // Нет новых уникальных пакетов
      }

      console.log(`Добавляем ${uniquePackets.length} уникальных пакетов`)

      // Проверяем на SYN-флуд атаку
      if (detectSynFlood([...packets, ...uniquePackets])) {
        uniquePackets.forEach((packet) => {
          if (packet.protocol === 6 && packet.flags === "S") {
            packet.isMalicious = true
          }
        })
      }

      // Обновляем состояние
      setPackets((prev) => [...prev, ...uniquePackets])

      // Обновляем статистику
      setCaptureStats((prev) => {
        const stats = { ...prev }
        stats.total += uniquePackets.length

        uniquePackets.forEach((packet) => {
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

        return stats
      })
    },
    [packets, getPacketHash],
  )

  // Update the connectToServer function to handle both packet data and command responses
  const connectToServer = useCallback(
    (interface_: string, filter: string) => {
      // Close previous connection
      if (wsRef.current) {
        wsRef.current.close()
      }

      // Clear the Set when making a new connection
      processedPacketsRef.current.clear()

      try {
        console.log("Connecting to Python WebSocket server...")

        // Create WebSocket connection to the Python server
        const ws = new WebSocket(`ws://localhost:8000?iface=${interface_}&filter=${filter}`)
        wsRef.current = ws

        ws.onopen = () => {
          console.log("Connected to Python WebSocket server")
          setIsCapturing(true)
          toast({
            title: "Подключено к серверу",
            description: "WebSocket соединение установлено",
          })
        }

        ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data)

            // Check if this is a command response or packet data
            if (data.type === "command_response") {
              console.log("Received command response:", data)
              // Handle command responses if needed
              if (data.command === "load_pcap" && data.status === "success") {
                toast({
                  title: "PCAP файл загружен",
                  description: `Загружено ${data.packet_count} пакетов`,
                })
              }
            } else {
              // Process the packet received from the Python server
              handleNewPackets([data])
            }
          } catch (error) {
            console.error("Error processing message:", error)
          }
        }

        ws.onerror = (error) => {
          console.error("WebSocket error:", error)
          setIsCapturing(false)
          toast({
            title: "Ошибка соединения",
            description: "Произошла ошибка при работе с WebSocket",
            variant: "destructive",
          })
        }

        ws.onclose = () => {
          console.log("WebSocket connection closed")
          setIsCapturing(false)
          toast({
            title: "Соединение закрыто",
            description: "WebSocket соединение с сервером закрыто",
          })
        }

        wsRef.current = ws
      } catch (error) {
        console.error("Error connecting to Python server:", error)
        setIsCapturing(false)
        toast({
          title: "Ошибка соединения",
          description: `Не удалось подключиться к серверу: ${error}`,
          variant: "destructive",
        })
      }
    },
    [handleNewPackets, toast],
  )

  // Функция для остановки захвата
  const stopCapture = useCallback(() => {
    if (wsRef.current) {
      wsRef.current.close()
      wsRef.current = null
    }
    setIsCapturing(false)
  }, [])

  // Функция для очистки пакетов
  const handleClearPackets = useCallback(() => {
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
    setMLAnalysisResults(null)
    // Очищаем Set для отслеживания пакетов
    processedPacketsRef.current.clear()
  }, [])

  // Callback для получения результатов ML анализа
  const handleMLAnalysisComplete = useCallback((results: any) => {
    console.log("Dashboard: ML Analysis completed:", results)
    setMLAnalysisResults(results)
  }, [])

  // Очищаем WebSocket соединение при размонтировании компонента
  useEffect(() => {
    return () => {
      if (wsRef.current) {
        wsRef.current.close()
      }
    }
  }, [])

  return (
    <div className="flex flex-col h-[calc(100vh-57px)]">
      <div className="flex-none">
        <PacketCapture
          isCapturing={isCapturing}
          setIsCapturing={(value) => {
            if (value) {
              const interface_ = "\\Device\\NPF_Loopback" // По умолчанию
              const filter = "" // Пустой фильтр по умолчанию
              connectToServer(interface_, filter)
            } else {
              stopCapture()
            }
          }}
          onNewPackets={handleNewPackets}
          onClearPackets={handleClearPackets}
          packets={packets}
          connectToServer={connectToServer}
          stopCapture={stopCapture}
          onMLAnalysisComplete={handleMLAnalysisComplete}
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
              <AnalysisPanel stats={captureStats} packets={packets} mlAnalysis={mlAnalysisResults} />
            </TabsContent>
          </Tabs>
        </div>
      </div>
    </div>
  )
}
