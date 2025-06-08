import asyncio
import json
import websockets
from scapy.all import AsyncSniffer, IP, TCP, UDP, Raw, send, rdpcap, wrpcap
import time
import hashlib
from random import randint
import os
import base64
import binascii

# Store connected WebSocket clients
connected_clients = set()
active_sniffers = {}

# Store seen packets to filter duplicates
seen_packets = set()
MAX_SEEN_PACKETS = 10000

# Временный файл для сохранения PCAP
TEMP_PCAP_FILE = "temp_capture.pcap"


def packet_hash(pkt):
    """Generate a unique hash for a packet based on its key fields"""
    key_parts = [
        pkt[IP].src if IP in pkt else "",
        pkt[IP].dst if IP in pkt else "",
        str(pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0)),
        str(pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0)),
        str(pkt[IP].proto if IP in pkt else 0),
        pkt.sprintf('%TCP.flags%') if TCP in pkt else "",
        str(len(pkt))
    ]
    return hashlib.md5(":".join(key_parts).encode()).hexdigest()


def is_duplicate(pkt):
    """Check if a packet is a duplicate based on its hash"""
    pkt_hash = packet_hash(pkt)

    # Check if we've seen this packet before
    if pkt_hash in seen_packets:
        return True

    # Add to seen packets
    seen_packets.add(pkt_hash)

    # Limit the size of seen_packets to prevent memory issues
    if len(seen_packets) > MAX_SEEN_PACKETS:
        # Remove oldest entries (approximation by removing random items)
        while len(seen_packets) > MAX_SEEN_PACKETS * 0.8:
            seen_packets.pop()

    return False


def packet_to_dict(pkt):
    """Convert a packet to a dictionary format for JSON serialization"""
    flags = ""
    if TCP in pkt:
        flags = pkt.sprintf('%TCP.flags%')
    is_syn = TCP in pkt and flags == "S"
    pkt_hash = packet_hash(pkt)

    # Преобразуем содержимое пакета в hex для отображения
    packet_hex = binascii.hexlify(bytes(pkt)).decode('utf-8')
    packet_hex_formatted = ' '.join(packet_hex[i:i + 2] for i in range(0, len(packet_hex), 2))

    return {
        "id": pkt_hash,
        "timestamp": time.time(),
        "sourceIp": pkt[IP].src if IP in pkt else "",
        "destIp": pkt[IP].dst if IP in pkt else "",
        "sourcePort": pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0),
        "destPort": pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0),
        "protocol": 6 if TCP in pkt else (17 if UDP in pkt else 1),
        "size": len(pkt),
        "flags": flags,
        "isMalicious": is_syn and pkt[TCP].dport == 80,
        "data": packet_hex_formatted
    }


async def broadcast_packet(packet_dict):
    """Broadcast a packet to all connected clients"""
    if connected_clients:
        message = json.dumps(packet_dict)
        await asyncio.gather(
            *[client.send(message) for client in connected_clients],
            return_exceptions=True
        )


async def capture_packets(websocket, iface, bpf_filter=""):
    """Capture packets and send them to the WebSocket client"""
    client_id = id(websocket)
    print(f"Starting capture for client {client_id} on interface {iface} with filter: {bpf_filter}")

    # Create a packet queue for this client
    queue = asyncio.Queue()

    # Function to process packets and filter duplicates
    def process_packet(pkt):
        if IP in pkt and not is_duplicate(pkt):
            # Выводим содержимое пакета в консоль
            print(f"Captured packet: {pkt.summary()}")
            print(f"Packet content: {binascii.hexlify(bytes(pkt)).decode('utf-8')}")
            queue.put_nowait(packet_to_dict(pkt))

    # Start the sniffer
    sniffer = AsyncSniffer(
        iface=iface,
        filter=bpf_filter,
        prn=process_packet,
        store=False
    )
    sniffer.start()
    active_sniffers[client_id] = sniffer

    try:
        while True:
            # Get packet from queue and send to client
            packet = await queue.get()
            await websocket.send(json.dumps(packet))
    except (asyncio.CancelledError, websockets.exceptions.ConnectionClosed):
        print(f"Capture stopped for client {client_id}")
    finally:
        # Stop the sniffer when done
        if client_id in active_sniffers:
            active_sniffers[client_id].stop()
            del active_sniffers[client_id]


async def generate_packets():
    """Generate SYN packets for testing"""
    target_ip = "127.0.0.1"

    while True:
        # Generate a random source IP and port
        src_ip = f"{randint(1, 254)}.{randint(1, 254)}.{randint(1, 254)}.{randint(1, 254)}"
        src_port = randint(1024, 65535)

        # Всегда отправляем SYN пакеты на порт 80
        target_port = 80
        pkt = IP(src=src_ip, dst=target_ip) / TCP(sport=src_port, dport=target_port, flags="S")
        print(f"Sending SYN packet from {src_ip}:{src_port} to {target_ip}:{target_port}")
        print(f"Packet content: {binascii.hexlify(bytes(pkt)).decode('utf-8')}")

        # Отправляем пакет
        send(pkt, verbose=0)

        # Задержка между отправкой пакетов
        await asyncio.sleep(0.5)


async def handle_websocket(websocket, path):
    """Handle WebSocket connections from clients"""
    client_id = id(websocket)
    print(f"New client connected: {client_id}, path: {path}")

    # Parse query parameters from the path
    query_params = {}
    if "?" in path:
        query_string = path.split("?")[1]
        for param in query_string.split("&"):
            if "=" in param:
                key, value = param.split("=", 1)
                query_params[key] = value

    # Get interface and filter from query parameters
    iface = query_params.get("iface", "\\Device\\NPF_Loopback")
    bpf_filter = query_params.get("filter", "")

    # Add client to connected clients set
    connected_clients.add(websocket)

    # Create tasks for command handling and packet capture
    command_task = None
    capture_task = None

    try:
        # Listen for commands from the client
        async def listen_for_commands():
            while True:
                try:
                    message = await websocket.recv()
                    print(f"Received message: {message}")
                    data = json.loads(message)

                    if "command" in data:
                        if data["command"] == "save_pcap":
                            # Сохраняем захваченные пакеты в PCAP файл
                            filename = data.get("filename", "capture.pcap")
                            print(f"Saving PCAP to {filename}")

                            # Отправляем подтверждение клиенту
                            await websocket.send(json.dumps({
                                "type": "command_response",
                                "command": "save_pcap",
                                "status": "success",
                                "filename": filename
                            }))
                        elif data["command"] == "load_pcap":
                            # Загружаем PCAP файл из base64 строки
                            if "pcap_data" in data:
                                try:
                                    pcap_bytes = base64.b64decode(data["pcap_data"])
                                    with open(TEMP_PCAP_FILE, "wb") as f:
                                        f.write(pcap_bytes)

                                    # Читаем пакеты из файла
                                    packets = rdpcap(TEMP_PCAP_FILE)
                                    print(f"Loaded {len(packets)} packets from PCAP")

                                    # Отправляем пакеты клиенту
                                    for pkt in packets:
                                        if IP in pkt:
                                            packet_dict = packet_to_dict(pkt)
                                            await websocket.send(json.dumps(packet_dict))

                                    # Отправляем подтверждение клиенту
                                    await websocket.send(json.dumps({
                                        "type": "command_response",
                                        "command": "load_pcap",
                                        "status": "success",
                                        "packet_count": len(packets)
                                    }))
                                except Exception as e:
                                    print(f"Error loading PCAP: {e}")
                                    await websocket.send(json.dumps({
                                        "type": "command_response",
                                        "command": "load_pcap",
                                        "status": "error",
                                        "error": str(e)
                                    }))
                except Exception as e:
                    print(f"Error processing command: {e}")
                    break

        # Start listening for commands in the background
        command_task = asyncio.create_task(listen_for_commands())

        # Start packet capture
        capture_task = asyncio.create_task(capture_packets(websocket, iface, bpf_filter))

        # Wait for either task to complete
        await asyncio.gather(command_task, capture_task)
    except Exception as e:
        print(f"Error in websocket handler: {e}")
    finally:
        # Clean up tasks
        if command_task and not command_task.done():
            command_task.cancel()
        if capture_task and not capture_task.done():
            capture_task.cancel()

        # Remove client when disconnected
        connected_clients.remove(websocket)
        print(f"Client disconnected: {client_id}")


async def main():
    # Clear seen packets at startup
    seen_packets.clear()

    # Start WebSocket server
    server = await websockets.serve(handle_websocket, "localhost", 8000)
    print("WebSocket server started on ws://localhost:8000")

    packet_generator_task = asyncio.create_task(generate_packets())

    await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
