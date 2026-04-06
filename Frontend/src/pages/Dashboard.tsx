import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Header } from "@/components/Header";
import { Footer } from "@/components/Footer";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { MessageCircle, ClipboardList, BookOpen, MapPin, FileText, Brain } from "lucide-react";
import { api } from "@/lib/api";
import { toast } from "sonner";

const Dashboard = () => {
  const navigate = useNavigate();
  const [user, setUser] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem('neuroaid_token');
    if (!token) {
      navigate('/login');
      return;
    }

    // Explicitly sync the ApiClient token before making the call
    api.setToken(token);

    const fetchUser = async () => {
      try {
        const userData = await api.getMe();
        setUser(userData);
      } catch (error) {
        // If the error is 401, clear everything and redirect
        api.clearToken();
        toast.error("Session expired. Please log in again.");
        navigate('/login');
      } finally {
        setLoading(false);
      }
    };

    fetchUser();
  }, [navigate]);

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-pulse text-primary">Loading...</div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex flex-col">
      <Header />
      
      <main className="flex-1 container mx-auto px-4 py-8">
        {/* Welcome Section */}
        <div className="mb-8">
          <h1 className="text-3xl md:text-4xl font-bold mb-2">
            Welcome back, {user?.display_name || 'there'}! 👋
          </h1>
          <p className="text-muted-foreground text-lg">
            Continue your mental health journey with our tools and resources.
          </p>
        </div>

        {/* Quick Actions */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-12">
          <Link to="/chat">
            <Card className="p-6 hover:shadow-medium transition-smooth cursor-pointer h-full">
              <div className="w-12 h-12 rounded-lg bg-primary/10 flex items-center justify-center mb-4">
                <MessageCircle className="h-6 w-6 text-primary" />
              </div>
              <h3 className="font-semibold mb-2">Start Chat</h3>
              <p className="text-sm text-muted-foreground">
                Talk with our AI assistant about your symptoms
              </p>
            </Card>
          </Link>

          <Link to="/tests">
            <Card className="p-6 hover:shadow-medium transition-smooth cursor-pointer h-full">
              <div className="w-12 h-12 rounded-lg bg-accent/10 flex items-center justify-center mb-4">
                <ClipboardList className="h-6 w-6 text-accent" />
              </div>
              <h3 className="font-semibold mb-2">Take a Test</h3>
              <p className="text-sm text-muted-foreground">
                Complete a validated screening assessment
              </p>
            </Card>
          </Link>

          <Link to="/diagnosis">
            <Card className="p-6 hover:shadow-medium transition-smooth cursor-pointer h-full">
              <div className="w-12 h-12 rounded-lg bg-info/10 flex items-center justify-center mb-4">
                <Brain className="h-6 w-6 text-info" />
              </div>
              <h3 className="font-semibold mb-2">Symptom Analysis</h3>
              <p className="text-sm text-muted-foreground">
                Get AI-powered analysis of your symptoms
              </p>
            </Card>
          </Link>

          <Link to="/consultants">
            <Card className="p-6 hover:shadow-medium transition-smooth cursor-pointer h-full">
              <div className="w-12 h-12 rounded-lg bg-success/10 flex items-center justify-center mb-4">
                <MapPin className="h-6 w-6 text-success" />
              </div>
              <h3 className="font-semibold mb-2">Find Help</h3>
              <p className="text-sm text-muted-foreground">
                Locate nearby mental health professionals
              </p>
            </Card>
          </Link>
        </div>

        {/* Resources Section */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <Card className="p-6">
            <div className="flex items-start gap-4 mb-4">
              <div className="w-10 h-10 rounded-lg bg-warning/10 flex items-center justify-center flex-shrink-0">
                <BookOpen className="h-5 w-5 text-warning" />
              </div>
              <div className="flex-1">
                <h3 className="font-semibold mb-2">Educational Resources</h3>
                <p className="text-sm text-muted-foreground mb-4">
                  Learn about mental health conditions, coping strategies, and treatment options.
                </p>
                <Link to="/learn">
                  <Button variant="outline" size="sm">Explore Resources</Button>
                </Link>
              </div>
            </div>
          </Card>

          <Card className="p-6">
            <div className="flex items-start gap-4 mb-4">
              <div className="w-10 h-10 rounded-lg bg-destructive/10 flex items-center justify-center flex-shrink-0">
                <FileText className="h-5 w-5 text-destructive" />
              </div>
              <div className="flex-1">
                <h3 className="font-semibold mb-2">Your Reports</h3>
                <p className="text-sm text-muted-foreground mb-4">
                  Access your assessment history and downloadable reports.
                </p>
                <Link to="/reports">
                  <Button variant="outline" size="sm">View Reports</Button>
                </Link>
              </div>
            </div>
          </Card>
        </div>

        {/* Important Notice */}
        <Card className="mt-8 p-6 border-warning/50 bg-warning/5">
          <div className="flex gap-3">
            <div className="text-warning flex-shrink-0">⚠️</div>
            <div>
              <h3 className="font-semibold mb-2">Important Notice</h3>
              <p className="text-sm text-muted-foreground">
                NeuroAid is a screening tool designed to help you understand potential mental health symptoms. 
                It is not a replacement for professional medical diagnosis or treatment. If you're experiencing 
                severe symptoms or having thoughts of self-harm, please contact a mental health professional 
                immediately or call 988 (Suicide & Crisis Lifeline).
              </p>
            </div>
          </div>
        </Card>
      </main>

      <Footer />
    </div>
  );
};

export default Dashboard;
