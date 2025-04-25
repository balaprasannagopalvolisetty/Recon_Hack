import { Terminal, Lock, Shield } from "lucide-react"

export const Footer = () => {
  return (
    <footer className="mt-16 py-6 text-center text-green-500 text-sm border-t border-green-800/30">
      <div className="flex items-center justify-center mb-2">
        <Terminal className="h-4 w-4 mr-1" />
        <Lock className="h-4 w-4 mx-1" />
        <Shield className="h-4 w-4 ml-1" />
      </div>
      <p className="cyber-glow">ReconAI - Advanced Web Reconnaissance Tool</p>
      <p className="mt-1 text-green-400 text-xs">
        Use responsibly and only on domains you own or have permission to scan.
      </p>
    </footer>
  )
}
