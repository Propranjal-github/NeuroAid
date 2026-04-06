import { useState, useEffect } from "react";
import { useNavigate, Link } from "react-router-dom";
import { Header } from "@/components/Header";
import { Footer } from "@/components/Footer";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Brain, Loader2, AlertCircle } from "lucide-react";
import { api } from "@/lib/api";
import { toast } from "sonner";

const Diagnosis = () => {
  const navigate = useNavigate();
  const [symptoms, setSymptoms] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);

  useEffect(() => {
    const token = localStorage.getItem('neuroaid_token');
    if (!token) {
      toast.error("Please log in to use symptom analysis");
      navigate('/login');
    }
  }, [navigate]);

  const handleAnalyze = async () => {
    if (!symptoms.trim()) {
      toast.error("Please describe your symptoms");
      return;
    }

    setLoading(true);
    setResult(null);

    try {
      const data = await api.runDiagnosis(symptoms);
      setResult(data);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Analysis failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex flex-col">
      <Header />
      
      <main className="flex-1 container mx-auto px-4 py-8">
        <div className="max-w-4xl mx-auto">
          <div className="mb-8">
            <h1 className="text-3xl md:text-4xl font-bold mb-2">Symptom Analysis</h1>
            <p className="text-muted-foreground text-lg">
              Describe your symptoms and get AI-powered insights
            </p>
          </div>

          {/* Important Warning */}
          <Card className="p-6 border-warning/50 bg-warning/5 mb-8">
            <div className="flex gap-3">
              <AlertCircle className="h-6 w-6 text-warning flex-shrink-0" />
              <div>
                <h3 className="font-semibold mb-2">Before You Continue</h3>
                <ul className="text-sm text-muted-foreground space-y-1">
                  <li>• This AI analysis is for informational purposes only</li>
                  <li>• It is NOT a medical diagnosis</li>
                  <li>• Always consult a healthcare professional for proper evaluation</li>
                  <li>• For emergencies, call 988 or visit your nearest emergency room</li>
                </ul>
              </div>
            </div>
          </Card>

          {/* Input Section */}
          <Card className="p-6 mb-6">
            <h3 className="text-lg font-semibold mb-4">Describe Your Symptoms</h3>
            <p className="text-sm text-muted-foreground mb-4">
              Be as specific as possible. Include details about when symptoms started, how often they occur, 
              and how they affect your daily life.
            </p>
            <Textarea
              placeholder="Example: For the past 3 months, I've had trouble concentrating at work. I often forget important tasks and feel restless during meetings. I also have difficulty organizing my daily activities..."
              value={symptoms}
              onChange={(e) => setSymptoms(e.target.value)}
              className="min-h-[200px] mb-4"
              disabled={loading}
            />
            <Button
              onClick={handleAnalyze}
              disabled={loading || !symptoms.trim()}
              className="w-full"
              size="lg"
            >
              {loading ? (
                <>
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  Analyzing...
                </>
              ) : (
                <>
                  <Brain className="h-4 w-4 mr-2" />
                  Analyze Symptoms
                </>
              )}
            </Button>
          </Card>

          {/* Results Section */}
          {result && (
            <>
              <Card className="p-6 mb-6">
                <h3 className="text-xl font-semibold mb-4">Analysis Results</h3>
                
                <div className="mb-4">
                  <div className="text-sm text-muted-foreground mb-2">Confidence Level</div>
                  <div className="flex items-center gap-3">
                    <div className="flex-1 bg-muted rounded-full h-3 overflow-hidden">
                      <div
                        className="h-full bg-gradient-primary transition-all"
                        style={{ width: `${result.confidence * 100}%` }}
                      />
                    </div>
                    <span className="text-sm font-medium">
                      {(result.confidence * 100).toFixed(0)}%
                    </span>
                  </div>
                </div>

                <div className="prose prose-sm max-w-none">
                  <p className="text-muted-foreground leading-relaxed whitespace-pre-wrap">
                    {result.interpretation}
                  </p>
                </div>
              </Card>

              <Card className="p-6 mb-6">
                <h3 className="text-lg font-semibold mb-3">Recommended Next Steps</h3>
                <ul className="space-y-2 text-muted-foreground text-sm">
                  <li>• Schedule an appointment with a mental health professional for proper evaluation</li>
                  <li>• Take one of our validated screening tests for more specific assessment</li>
                  <li>• Keep a journal of your symptoms to share with your healthcare provider</li>
                  <li>• Explore our educational resources to learn more about potential conditions</li>
                  <li>• Find qualified professionals in your area using our consultant directory</li>
                </ul>
              </Card>

              <div className="flex flex-col sm:flex-row gap-4">
                <Link to="/tests" className="flex-1">
                  <Button variant="default" className="w-full">Take a Screening Test</Button>
                </Link>
                <Link to="/consultants" className="flex-1">
                  <Button variant="outline" className="w-full">Find a Professional</Button>
                </Link>
                <Link to="/chat" className="flex-1">
                  <Button variant="outline" className="w-full">Chat with AI</Button>
                </Link>
              </div>
            </>
          )}

          {/* Additional Info */}
          {!result && (
            <Card className="p-6 bg-muted/30">
              <h3 className="font-semibold mb-3">How This Works</h3>
              <ul className="space-y-2 text-sm text-muted-foreground">
                <li>• Our AI analyzes your symptom description using advanced language models</li>
                <li>• Results indicate possible conditions based on patterns in your description</li>
                <li>• Higher confidence levels suggest stronger symptom patterns</li>
                <li>• This tool complements, but never replaces, professional medical advice</li>
              </ul>
            </Card>
          )}
        </div>
      </main>

      <Footer />
    </div>
  );
};

export default Diagnosis;
