import Link from "next/link"
import { Button } from "@/components/ui/button"

export default function Home() {
  return (
    <div className="flex flex-col min-h-screen">
      <header className="border-b bg-background px-4 py-3">
        <div className="flex items-center justify-between max-w-7xl mx-auto">
          <h1 className="text-xl font-bold">Network Traffic Analyzer</h1>
          <div className="flex gap-4">
            <Link href="/login">
              <Button variant="outline">Log In</Button>
            </Link>
            <Link href="/signup">
              <Button>Sign Up</Button>
            </Link>
          </div>
        </div>
      </header>
      <main className="flex-1 flex flex-col items-center justify-center p-6">
        <div className="max-w-3xl text-center space-y-6">
          <h2 className="text-4xl font-bold tracking-tight">Analyze Your Network Traffic</h2>
          <p className="text-xl text-muted-foreground">
            Monitor, analyze, and detect threats in your network traffic with our advanced tools.
          </p>
          <div className="flex justify-center gap-4">
            <Link href="/signup">
              <Button size="lg">Get Started</Button>
            </Link>
            <Link href="/login">
              <Button variant="outline" size="lg">
                Log In
              </Button>
            </Link>
          </div>
        </div>
      </main>
      <footer className="border-t py-6 text-center text-sm text-muted-foreground">
        <p>© 2025 Network Traffic Analyzer. All rights reserved.</p>
      </footer>
    </div>
  )
}
