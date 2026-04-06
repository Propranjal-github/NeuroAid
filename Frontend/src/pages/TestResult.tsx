import { useLocation, useNavigate, Link } from "react-router-dom";
import { Header } from "@/components/Header";
import { Footer } from "@/components/Footer";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { CheckCircle, AlertTriangle, Info } from "lucide-react";

const TestResult = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const result = location.state?.result;

  if (!result) {
    navigate('/tests');
    return null;
  }

  const getSeverityIcon = () => {
    if (result.confidence > 0.7) return <AlertTriangle className="h-8 w-8 text-warning" />;
    if (result.confidence > 0.4) return <Info className="h-8 w-8 text-info" />;
    return <CheckCircle className="h-8 w-8 text-success" />;
  };

  const getSeverityColor = () => {
    if (result.confidence > 0.7) return "border-warning/50 bg-warning/5";
    if (result.confidence > 0.4) return "border-info/50 bg-info/5";
    return "border-success/50 bg-success/5";
  };

  return (
    <div className="min-h-screen flex flex-col">
      <Header />
      
      <main className="flex-1 container mx-auto px-4 py-8">
        <div className="max-w-3xl mx-auto">
          <div className="text-center mb-8">
            <h1 className="text-3xl font-bold mb-2">Your Assessment Results</h1>
            <p className="text-muted-foreground">
              {result.type} - Completed {new Date().toLocaleDateString()}
            </p>
          </div>

          {/* Score Card */}
          <Card className={`p-8 mb-6 ${getSeverityColor()}`}>
            <div className="flex flex-col items-center text-center space-y-4">
              {getSeverityIcon()}
              <div>
                <h2 className="text-2xl font-bold mb-2">Score: {result.score}</h2>
                <p className="text-lg text-muted-foreground">
                  Confidence: {(result.confidence * 100).toFixed(0)}%
                </p>
              </div>
            </div>
          </Card>

          {/* Interpretation */}
          <Card className="p-6 mb-6">
            <h3 className="text-xl font-semibold mb-3">What This Means</h3>
            <p className="text-muted-foreground leading-relaxed">
              {result.interpretation}
            </p>
          </Card>

          {/* Recommendations */}
          <Card className="p-6 mb-6">
            <h3 className="text-xl font-semibold mb-3">Next Steps</h3>
            <ul className="space-y-2 text-muted-foreground">
              {result.confidence > 0.5 && (
                <li>• Consider scheduling an appointment with a mental health professional for a formal evaluation</li>
              )}
              <li>• Keep track of your symptoms and how they affect your daily life</li>
              <li>• Learn more about this condition in our educational resources</li>
              <li>• Chat with our AI assistant for more personalized guidance</li>
              <li>• Save this assessment to monitor your progress over time</li>
            </ul>
          </Card>

          {/* Important Disclaimer */}
          <Card className="p-6 border-destructive/30 bg-destructive/5 mb-6">
            <h3 className="font-semibold mb-2 flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-destructive" />
              Important Reminder
            </h3>
            <p className="text-sm text-muted-foreground">
              This is a screening tool, not a clinical diagnosis. Only a qualified healthcare provider 
              can provide an official diagnosis. If you're experiencing severe symptoms or having 
              thoughts of self-harm, please contact a mental health professional immediately or call 988.
            </p>
          </Card>

          {/* Action Buttons */}
          <div className="flex flex-col sm:flex-row gap-4">
            <Link to="/consultants" className="flex-1">
              <Button className="w-full" variant="default">Find a Professional</Button>
            </Link>
            <Link to="/learn" className="flex-1">
              <Button className="w-full" variant="outline">Learn More</Button>
            </Link>
            <Link to="/chat" className="flex-1">
              <Button className="w-full" variant="outline">Chat with AI</Button>
            </Link>
          </div>
        </div>
      </main>

      <Footer />
    </div>
  );
};

export default TestResult;
