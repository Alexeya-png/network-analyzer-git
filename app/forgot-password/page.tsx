import { ForgotPasswordForm } from "@/components/auth/forgot-password-form"
import Link from "next/link"

export default function ForgotPasswordPage() {
  return (
    <div className="flex min-h-screen flex-col">
      <header className="border-b bg-background px-4 py-3">
        <div className="flex items-center max-w-7xl mx-auto">
          <Link href="/" className="text-xl font-bold">
            Network Traffic Analyzer
          </Link>
        </div>
      </header>
      <main className="flex-1 flex items-center justify-center p-6">
        <ForgotPasswordForm />
      </main>
    </div>
  )
}
