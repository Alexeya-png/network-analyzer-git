export interface PacketData {
  id: number
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
}