import { Shield, Terminal } from "lucide-react"

export const Header = () => {
  return (
    <header className="flex justify-between items-center py-4">
      <div className="flex items-center">
        <div className="relative mr-3">
          <Shield className="h-8 w-8 text-green-500" />
          <div className="absolute inset-0 bg-green-500/20 rounded-full animate-pulse"></div>
        </div>
        <div>
          <h1 className="glitch text-2xl font-bold text-green-500" data-text="ReconAI">
            ReconAI
          </h1>
          <div className="flex items-center">
            <Terminal className="h-3 w-3 text-green-400 mr-1" />
            <p className="text-green-400 text-xs terminal-text">Advanced Web Reconnaissance Tool</p>
          </div>
        </div>
      </div>
    </header>
  )
}
