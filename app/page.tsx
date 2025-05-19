import { Dashboard } from "@/components/dashboard"

export default function Home() {
  return (
    <div className="flex flex-col min-h-screen">
      <header className="border-b bg-background px-4 py-3">
        <div className="flex items-center justify-between">
          <h1 className="text-xl font-bold">Network Traffic Analyzer</h1>
        </div>
      </header>
      <Dashboard />
    </div>
  )
}