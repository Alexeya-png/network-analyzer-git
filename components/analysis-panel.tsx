"use client"

import React from "react"

import { useState, useEffect } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Progress } from "@/components/ui/progress"
import type { PacketData } from "@/lib/types"
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from "recharts"

interface AnalysisPanelProps {
  stats: {
    total: number
    malicious: number
    tcp: number
    udp: number
    icmp: number
    other: number
  }
  packets: PacketData[]
  mlAnalysis?: {
    total: number
    malicious: number
    benign: number
    accuracy: number
  }
}

export function AnalysisPanel({ stats, packets, mlAnalysis }: AnalysisPanelProps) {
  const [threatLevel, setThreatLevel] = useState(0)

  useEffect(() => {
    // Calculate threat level based on percentage of malicious packets
    if (stats.total === 0) {
      setThreatLevel(0)
    } else {
      const maliciousPercentage = (stats.malicious / stats.total) * 100
      setThreatLevel(maliciousPercentage > 50 ? 100 : maliciousPercentage * 2)
    }
  }, [stats])

  const protocolData = [
    { name: "TCP", value: stats.tcp },
    { name: "UDP", value: stats.udp },
    { name: "ICMP", value: stats.icmp },
    { name: "Other", value: stats.other },
  ]

  const COLORS = ["#0088FE", "#00C49F", "#FFBB28", "#FF8042"]

  // Calculate top talkers (most active IP addresses)
  const topTalkers = React.useMemo(() => {
    const ipCounts: Record<string, number> = {}

    packets.forEach((packet) => {
      ipCounts[packet.sourceIp] = (ipCounts[packet.sourceIp] || 0) + 1
      ipCounts[packet.destIp] = (ipCounts[packet.destIp] || 0) + 1
    })

    return Object.entries(ipCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([ip, count]) => ({ ip, count }))
  }, [packets])

  return (
    <div className="p-4 space-y-6">
      <Card>
        <CardHeader className="pb-2">
          <CardTitle>Аналіз загроз</CardTitle>
          <CardDescription>
            Виявлено {stats.malicious} потенційно небезпечних із {stats.total} пакетів
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            <div className="flex justify-between">
              <span>Рівень загрози</span>
              <span
                className={`font-medium ${
                  threatLevel < 30 ? "text-green-500" : threatLevel < 70 ? "text-yellow-500" : "text-red-500"
                }`}
              >
                {threatLevel < 30 ? "Низький" : threatLevel < 70 ? "Середній" : "Високий"}
              </span>
            </div>
            <Progress
              value={threatLevel}
              className={`h-2 ${threatLevel < 30 ? "bg-green-100" : threatLevel < 70 ? "bg-yellow-100" : "bg-red-100"}`}
            />
          </div>

          {stats.malicious > 0 && (
            <div className="mt-4 p-3 bg-red-50 border border-red-200 rounded-md text-sm dark:bg-red-900/20 dark:border-red-800">
              <p className="font-medium text-red-800 dark:text-red-400">Виявлено підозрілу активність</p>
              <p className="text-red-600 mt-1 dark:text-red-400">
                Зафіксовано нетиповий мережевий трафік, що може вказувати на атаку.
              </p>
            </div>
          )}
        </CardContent>
      </Card>

      {mlAnalysis && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle>Аналіз машинного навчання</CardTitle>
            <CardDescription>Результати Random Forest моделі</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="text-center">
                  <div className="text-2xl font-bold text-red-500">{mlAnalysis.malicious}</div>
                  <div className="text-sm text-muted-foreground">Шкідливі</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-green-500">{mlAnalysis.benign}</div>
                  <div className="text-sm text-muted-foreground">Безпечні</div>
                </div>
              </div>
              <div className="text-center">
                <div className="text-lg font-semibold">Точність моделі: {(mlAnalysis.accuracy * 100).toFixed(1)}%</div>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle>Protocol Distribution</CardTitle>
          </CardHeader>
          <CardContent className="h-[200px]">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={protocolData}
                  cx="50%"
                  cy="50%"
                  labelLine={false}
                  outerRadius={80}
                  fill="#8884d8"
                  dataKey="value"
                  label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                >
                  {protocolData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle>Top Talkers</CardTitle>
          </CardHeader>
          <CardContent className="h-[200px]">
            {topTalkers.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={topTalkers} margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="ip" />
                  <YAxis />
                  <Tooltip />
                  <Bar dataKey="count" fill="#8884d8" />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex items-center justify-center h-full text-muted-foreground">No data available</div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
