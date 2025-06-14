export interface PacketData {
  id: string | number
  timestamp: string
  sourceIp: string
  destIp: string
  sourcePort: number
  destPort: number
  protocol: number // 1=ICMP, 6=TCP, 17=UDP, etc.
  size: number
  flags: string
  isMalicious: boolean
  data: string // Hex representation of packet data
  mlConfidence?: number // ML model confidence score (0-1)
}
