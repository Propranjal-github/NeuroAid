import { useState, useRef, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { Header } from "@/components/Header";
import { Footer } from "@/components/Footer";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card } from "@/components/ui/card";
import { Send, Loader2, MessageSquare, Plus } from "lucide-react";
import { api, Conversation } from "@/lib/api";
import { toast } from "sonner";

interface ChatMessage {
  id: string;
  sender: 'user' | 'assistant' | 'system';
  content: string;
  timestamp: Date;
}

const DEFAULT_MESSAGE: ChatMessage = {
  id: '1',
  sender: 'system',
  content: '⚠️ This is a screening tool, not a clinical diagnosis. Your conversation will be stored securely. Be honest about your symptoms for the best guidance.',
  timestamp: new Date(),
};

const Chat = () => {
  const navigate = useNavigate();
  const [messages, setMessages] = useState<ChatMessage[]>([DEFAULT_MESSAGE]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [conversationId, setConversationId] = useState<string | undefined>();
  const [conversations, setConversations] = useState<Conversation[]>([]);
  const [loadingHistory, setLoadingHistory] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const token = localStorage.getItem('neuroaid_token');
    if (!token) {
      toast.error("Please log in to use chat");
      navigate('/login');
      return;
    }
    loadHistory();
  }, [navigate]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const loadHistory = async () => {
    try {
      const response = await api.getChatHistory();
      setConversations(response.conversations || []);
    } catch (err) {
      console.error("Failed to load history", err);
    }
  };

  const startNewChat = () => {
    setConversationId(undefined);
    setMessages([DEFAULT_MESSAGE]);
  };

  const selectConversation = async (id: string) => {
    if (id === conversationId) return;
    setLoadingHistory(true);
    try {
      const response = await api.getChatMessages(id);
      const historyMessages = response.messages.map(m => ({
        id: m.id.toString(),
        sender: m.sender,
        content: m.content,
        timestamp: new Date(m.created_at)
      }));
      setMessages([DEFAULT_MESSAGE, ...historyMessages]);
      setConversationId(id);
    } catch (err) {
      toast.error("Failed to load conversation");
    } finally {
      setLoadingHistory(false);
    }
  };

  const handleSend = async () => {
    if (!input.trim() || loading) return;

    const userMessage: ChatMessage = {
      id: Date.now().toString(),
      sender: 'user',
      content: input,
      timestamp: new Date(),
    };

    setMessages(prev => [...prev, userMessage]);
    setInput("");
    setLoading(true);

    try {
      const response = await api.sendMessage(input, conversationId);
      
      if (!conversationId) {
        setConversationId(response.conversation_id);
      }

      const assistantMessage: ChatMessage = {
        id: (Date.now() + 1).toString(),
        sender: 'assistant',
        content: response.response,
        timestamp: new Date(),
      };

      setMessages(prev => [...prev, assistantMessage]);
      setTimeout(loadHistory, 1000);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Failed to send message");
      setMessages(prev => prev.slice(0, -1)); // Remove user message on error
    } finally {
      setLoading(false);
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  return (
    <div className="min-h-screen flex flex-col bg-background">
      <Header />
      
      <main className="flex-1 container mx-auto px-4 py-4 flex flex-col md:flex-row max-w-6xl gap-6">
        
        {/* Sidebar History */}
        <aside className="w-full md:w-64 flex flex-col gap-4 border-b md:border-b-0 md:border-r pr-0 md:pr-4 pb-4 md:pb-0 max-h-[250px] md:max-h-[700px] overflow-y-auto shrink-0">
          <Button variant="outline" className="w-full justify-start gap-2" onClick={startNewChat}>
            <Plus className="h-4 w-4" />
            New Chat
          </Button>
          <div className="flex flex-col gap-2 relative flex-1">
            {loadingHistory && (
               <div className="absolute inset-0 bg-background/50 flex align-center justify-center z-10 pt-4">
                 <Loader2 className="h-6 w-6 animate-spin text-primary" />
               </div>
            )}
            <h3 className="text-sm font-semibold text-muted-foreground mt-2 px-2">Recent Sessions</h3>
            {conversations.length === 0 ? (
              <p className="text-xs text-muted-foreground px-2">No past conversations.</p>
            ) : (
              conversations.map(conv => (
                <Button 
                  key={conv.id} 
                  variant={conversationId === conv.id ? "secondary" : "ghost"} 
                  className="w-full justify-start font-normal text-left flex flex-col items-start h-auto py-2"
                  onClick={() => selectConversation(conv.id)}
                >
                  <div className="flex items-center gap-2 w-full">
                    <MessageSquare className="h-4 w-4 shrink-0 text-muted-foreground" />
                    <span className="truncate flex-1 font-medium">{conv.title}</span>
                  </div>
                  {conv.summary_snippet && (
                    <span className="text-xs text-muted-foreground line-clamp-2 w-full pl-6 mt-1 text-left">
                      {conv.summary_snippet}
                    </span>
                  )}
                </Button>
              ))
            )}
          </div>
        </aside>

        {/* Chat Area */}
        <div className="flex-1 flex flex-col flex-grow w-full max-w-full min-w-0">
          <div className="mb-6 hidden md:block">
            <h1 className="text-3xl font-bold mb-2">AI Chat Assistant</h1>
            <p className="text-muted-foreground">
              Discuss your symptoms and concerns with our trained AI assistant
            </p>
          </div>

          {/* Messages Area */}
          <Card className="flex-1 p-4 mb-4 overflow-y-auto min-h-[400px] max-h-[600px] space-y-4">
            {messages.map((message) => (
              <div
                key={message.id}
                className={`flex ${message.sender === 'user' ? 'justify-end' : 'justify-start'}`}
              >
                <div
                  className={`max-w-[90%] md:max-w-[80%] rounded-lg p-4 ${
                    message.sender === 'user'
                      ? 'bg-primary text-primary-foreground'
                      : message.sender === 'system'
                      ? 'bg-warning/10 text-warning-foreground border border-warning/20'
                      : 'bg-muted text-foreground'
                  }`}
                >
                  <p className="text-sm whitespace-pre-wrap">{message.content}</p>
                  <span className="text-xs opacity-70 mt-2 block w-full text-right">
                    {message.timestamp.toLocaleTimeString()}
                  </span>
                </div>
              </div>
            ))}
            {loading && (
              <div className="flex justify-start">
                <div className="bg-muted rounded-lg p-4 flex items-center gap-2">
                  <Loader2 className="h-4 w-4 animate-spin" />
                  <span className="text-sm">Thinking...</span>
                </div>
              </div>
            )}
            <div ref={messagesEndRef} />
          </Card>

          {/* Input Area */}
          <div className="flex gap-2">
            <Input
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyPress={handleKeyPress}
              placeholder="Describe your symptoms or ask a question..."
              disabled={loading || loadingHistory}
              className="flex-1"
            />
            <Button onClick={handleSend} disabled={loading || loadingHistory || !input.trim()}>
              {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />}
            </Button>
          </div>

          <p className="text-xs text-muted-foreground mt-2 text-center">
            Press Enter to send, Shift+Enter for new line
          </p>
        </div>
      </main>

      <Footer />
    </div>
  );
};

export default Chat;
