"use client"

import { useState } from "react"
import { MessageSquare, X, Shield, Cpu, AlertTriangle } from "lucide-react"
import { Button } from "@/components/ui/button"
import { ChatInterface } from "./chat-interface"
import type { ScanResult } from "./recon-dashboard"

interface NavbarProps {
  scanResult?: ScanResult | null
}

export function Navbar({ scanResult }: NavbarProps) {
  const [isChatOpen, setIsChatOpen] = useState(false)

  return (
    <>
      <nav className="fixed top-0 left-0 right-0 z-50 bg-black/80 border-b border-green-500/30 backdrop-blur-sm">
        <div className="container mx-auto px-4">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center">
              <Shield className="h-6 w-6 text-green-500 mr-2" />
              <span className="text-green-500 font-bold terminal-text">ReconAI</span>
              <div className="ml-4 h-2 w-2 bg-green-500 rounded-full animate-pulse"></div>
              <span className="ml-2 text-green-400 text-xs terminal-text">SYSTEM ACTIVE</span>
            </div>

            <div className="flex items-center space-x-4">
              <div className="hidden md:flex items-center space-x-4">
                <div className="flex items-center text-green-400 text-xs">
                  <Cpu className="h-4 w-4 mr-1 text-green-500" />
                  <span className="terminal-text">ALIENTELLIGENCE/predictivethreatdetection</span>
                </div>
                <div className="h-4 w-[1px] bg-green-500/30"></div>
                <div className="flex items-center text-green-400 text-xs">
                  <AlertTriangle className="h-4 w-4 mr-1 text-green-500" />
                  <span className="terminal-text">THREAT ANALYSIS READY</span>
                </div>
              </div>

              <Button variant="outline" size="sm" className="cyber-glow" onClick={() => setIsChatOpen(!isChatOpen)}>
                {isChatOpen ? (
                  <>
                    <X className="h-4 w-4 mr-2" />
                    <span className="terminal-text">Close AI</span>
                  </>
                ) : (
                  <>
                    <MessageSquare className="h-4 w-4 mr-2" />
                    <span className="terminal-text">AI Chat</span>
                  </>
                )}
              </Button>
            </div>
          </div>
        </div>
      </nav>

      {/* Chat Interface */}
      <div
        className={`fixed right-0 top-16 bottom-0 w-full md:w-96 bg-black/90 border-l border-green-500/30 transform transition-transform duration-300 ease-in-out z-40 ${
          isChatOpen ? "translate-x-0" : "translate-x-full"
        }`}
      >
        <ChatInterface onClose={() => setIsChatOpen(false)} scanResult={scanResult} />
      </div>

      {/* Overlay when chat is open on mobile */}
      {isChatOpen && (
        <div className="fixed inset-0 bg-black/50 z-30 md:hidden" onClick={() => setIsChatOpen(false)}></div>
      )}
    </>
  )
}
