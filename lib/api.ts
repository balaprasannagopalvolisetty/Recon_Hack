/**
 * API client for the ReconAI backend
 */

// Base URL for API requests
export const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"

/**
 * Start a new scan
 */
export async function startScan(data: { url: string; modules: string[]; use_llm?: boolean }): Promise<any> {
  const response = await fetch(`${API_BASE_URL}/api/scan`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(data),
  })

  if (!response.ok) {
    const error = await response.json()
    throw new Error(error.detail || "Failed to start scan")
  }

  return response.json()
}

/**
 * Get scan result by ID
 */
export async function getScanResult(scanId: string): Promise<any> {
  const response = await fetch(`${API_BASE_URL}/api/scan/${scanId}`)

  if (!response.ok) {
    const error = await response.json()
    throw new Error(error.detail || "Failed to get scan result")
  }

  return response.json()
}

/**
 * Analyze scan results using AI
 */
export async function analyzeScan(data: { scan_id: string; query: string; use_llm?: boolean }): Promise<any> {
  const response = await fetch(`${API_BASE_URL}/api/analyze`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(data),
  })

  if (!response.ok) {
    const error = await response.json()
    throw new Error(error.detail || "Failed to analyze scan")
  }

  return response.json()
}

/**
 * Submit feedback for a scan finding
 */
export async function submitFeedback(data: {
  scan_id: string
  module: string
  finding_id: string
  is_true_positive: boolean
  comment?: string
}): Promise<any> {
  const response = await fetch(`${API_BASE_URL}/api/feedback`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(data),
  })

  if (!response.ok) {
    const error = await response.json()
    throw new Error(error.detail || "Failed to submit feedback")
  }

  return response.json()
}

/**
 * Train the model with collected feedback
 */
export async function trainModel(data: {
  name: string
  description: string
  base_model?: string
  verification_code: string
}): Promise<any> {
  const response = await fetch(`${API_BASE_URL}/api/train`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(data),
  })

  if (!response.ok) {
    const error = await response.json()
    throw new Error(error.detail || "Failed to train model")
  }

  return response.json()
}

/**
 * Get application settings
 */
export async function getSettings(): Promise<any> {
  const response = await fetch(`${API_BASE_URL}/api/settings`)

  if (!response.ok) {
    const error = await response.json()
    throw new Error(error.detail || "Failed to get settings")
  }

  return response.json()
}

/**
 * Update application settings
 */
export async function updateSettings(data: {
  enable_llm: boolean
  default_llm_model: string
}): Promise<any> {
  const formData = new FormData()
  formData.append("enable_llm", data.enable_llm.toString())
  formData.append("default_llm_model", data.default_llm_model)

  const response = await fetch(`${API_BASE_URL}/api/settings`, {
    method: "POST",
    body: formData,
  })

  if (!response.ok) {
    const error = await response.json()
    throw new Error(error.detail || "Failed to update settings")
  }

  return response.json()
}
