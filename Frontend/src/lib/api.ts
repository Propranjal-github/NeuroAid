// API client for NeuroAid Flask backend
const API_BASE_URL = import.meta.env.VITE_API_URL || 'https://neuroaid-ix03.onrender.com';

export interface User {
  id: number;
  email: string;
  display_name: string;
  role?: string;
}

export interface AuthResponse {
  token: string;
  user: User;
}

export interface Message {
  id: number;
  sender: 'user' | 'assistant' | 'system';
  content: string;
  created_at: string;
}

export interface Conversation {
  id: string;
  title: string;
  created_at: string;
  last_updated_at?: string;
  summary_snippet?: string;
}

class ApiClient {
  private token: string | null = null;

  constructor() {
    this.token = localStorage.getItem('neuroaid_token');
  }

  setToken(token: string) {
    this.token = token;
    localStorage.setItem('neuroaid_token', token);
  }

  clearToken() {
    this.token = null;
    localStorage.removeItem('neuroaid_token');
  }

  getToken() {
    return this.token;
  }

  private async request<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> {
    const headers: HeadersInit = {
      'Content-Type': 'application/json',
      ...options.headers,
    };

    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }

    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      ...options,
      headers,
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ error: 'Request failed' }));
      throw new Error(error.error || `HTTP ${response.status}`);
    }

    return response.json();
  }

  // Auth
  async signup(email: string, password: string, display_name: string): Promise<AuthResponse> {
    return this.request<AuthResponse>('/auth/signup', {
      method: 'POST',
      body: JSON.stringify({ email, password, display_name }),
    });
  }

  async login(email: string, password: string): Promise<AuthResponse> {
    return this.request<AuthResponse>('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
  }

  async getMe(): Promise<User> {
    return this.request<User>('/auth/me');
  }

  // Google OAuth - redirects to backend OAuth flow
  getGoogleLoginUrl(): string {
    return `${API_BASE_URL}/auth/google/login`;
  }

  // Chat
  async getChatHistory() {
    return this.request<{
      conversations: Conversation[];
    }>('/chat/history');
  }

  async getChatMessages(conversationId: string) {
    return this.request<{
      messages: Message[];
    }>(`/chat/history/${conversationId}`);
  }
  async sendMessage(message: string, conversation_id?: string) {
    return this.request<{
      conversation_id: string;
      response: string;
      summary: string;
      meta: any;
    }>('/chat', {
      method: 'POST',
      body: JSON.stringify({ message, conversation_id }),
    });
  }

  // Diagnosis
  async runDiagnosis(symptoms: string) {
    return this.request<{
      assessment_id: number;
      interpretation: string;
      confidence: number;
      raw: any;
    }>('/diagnosis', {
      method: 'POST',
      body: JSON.stringify({ symptoms }),
    });
  }

  // Tests
  async getTest(disorder: string) {
    return this.request<{
      type: string;
      questions: Array<{ id: string; text: string }>;
    }>(`/tests/${disorder}`);
  }

  async submitTest(type: string, answers: Record<string, number>) {
    return this.request<{
      assessment_id: number;
      type: string;
      score: number;
      confidence: number;
      interpretation: string;
    }>('/tests/submit', {
      method: 'POST',
      body: JSON.stringify({ type, answers }),
    });
  }

  // Reports
  async getReports() {
    return this.request<{
      reports: Array<{
        id: number;
        title: string;
        date: string;
        score: number;
        type: string;
        confidence: number;
        interpretation?: string;
      }>;
    }>('/reports');
  }

  // Learn
  async getLearnContent(topic: string) {
    return this.request<{
      items: Array<{
        id: number;
        title: string;
        type: string;
        url: string;
        summary: string;
        tags: string[];
      }>;
    }>(`/learn/${topic}`);
  }

  // Consultants
  async getConsultants(lat: number, lng: number, q?: string) {
    const params = new URLSearchParams({
      lat: lat.toString(),
      lng: lng.toString(),
      ...(q && { q }),
    });
    return this.request<{
      results: Array<{
        name: string;
        vicinity?: string;
        place_id: string;
        types?: string[];
        lat?: number;
        lng?: number;
      }>;
    }>(`/consultants?${params}`);
  }

  // Contact
  async sendContact(message: string, name?: string, email?: string) {
    return this.request<{ status: string; id: number }>('/contact', {
      method: 'POST',
      body: JSON.stringify({ message, name, email }),
    });
  }
}

export const api = new ApiClient();
