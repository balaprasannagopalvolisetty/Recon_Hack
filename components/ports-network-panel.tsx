"use client"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Network, Shield, Server } from "lucide-react"

interface PortsNetworkPanelProps {
  data: any
}

export function PortsNetworkPanel({ data }: PortsNetworkPanelProps) {
  if (!data) return null

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center">
            <Network className="mr-2 h-5 w-5" />
            Open Ports
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-700">
                    <th className="text-left py-2 px-4">Port</th>
                    <th className="text-left py-2 px-4">Service</th>
                    <th className="text-left py-2 px-4">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {data.openPorts &&
                    data.openPorts.map((port: number, i: number) => (
                      <tr key={i} className="border-b border-gray-800">
                        <td className="py-2 px-4">{port}</td>
                        <td className="py-2 px-4">{data.services[port] || "Unknown"}</td>
                        <td className="py-2 px-4">
                          <Badge variant="success">Open</Badge>
                        </td>
                      </tr>
                    ))}
                  {(!data.openPorts || data.openPorts.length === 0) && (
                    <tr>
                      <td colSpan={3} className="py-4 text-center text-gray-400">
                        No open ports detected
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </CardContent>
      </Card>

      {data.firewalls && data.firewalls.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center">
              <Shield className="mr-2 h-5 w-5" />
              Firewalls & WAFs
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {data.firewalls.map((firewall: string, i: number) => (
                <div key={i} className="flex items-center space-x-2">
                  <Shield className="h-4 w-4 text-blue-400" />
                  <span>{firewall}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {data.topology && data.topology.hops && data.topology.hops.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center">
              <Server className="mr-2 h-5 w-5" />
              Network Topology
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-gray-700">
                      <th className="text-left py-2 px-4">Hop</th>
                      <th className="text-left py-2 px-4">Host</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.topology.hops.map((hop: any, i: number) => (
                      <tr key={i} className="border-b border-gray-800">
                        <td className="py-2 px-4">{hop.hop}</td>
                        <td className="py-2 px-4">{hop.host}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
