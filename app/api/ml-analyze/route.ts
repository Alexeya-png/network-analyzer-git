import { NextResponse } from "next/server"

// Эта функция будет обрабатывать запросы на анализ пакетов
// В реальной реализации здесь был бы вызов Python сервера с ML моделью
export async function POST(request: Request) {
  try {
    const { features } = await request.json()

    if (!features || !Array.isArray(features)) {
      return NextResponse.json({ error: "Invalid features data" }, { status: 400 })
    }

    // Симуляция анализа ML модели
    // В реальной реализации здесь был бы вызов Python сервера
    const predictions = features.map((feature: any) => {
      // Простая эвристика для демонстрации
      // SYN пакеты на порт 80 считаем подозрительными
      const isSynToPort80 = feature.protocol === 6 && feature.dst_port === 80
      const hasRandomSourceIP = feature.src_ip > 0

      // Если это SYN пакет на порт 80 с случайным IP - вероятно атака
      return isSynToPort80 && hasRandomSourceIP
    })

    const confidence = predictions.map(
      (pred: boolean) => (pred ? Math.random() * 0.3 + 0.7 : Math.random() * 0.3 + 0.1), // 0.7-1.0 для malicious, 0.1-0.4 для benign
    )

    const maliciousCount = predictions.filter((p: boolean) => p).length

    const result = {
      predictions,
      confidence,
      summary: {
        total: features.length,
        malicious: maliciousCount,
        benign: features.length - maliciousCount,
        accuracy: 0.85, // Симулированная точность модели
      },
    }

    return NextResponse.json(result)
  } catch (error) {
    console.error("Error in ML analysis:", error)
    return NextResponse.json({ error: "Internal server error" }, { status: 500 })
  }
}
