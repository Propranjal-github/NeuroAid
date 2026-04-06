import { Link } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Brain, MessageCircle, ClipboardList, BookOpen, Users, Shield } from "lucide-react";
import { Header } from "@/components/Header";
import { Footer } from "@/components/Footer";

const Landing = () => {
  return (
    <div className="min-h-screen flex flex-col">
      <Header />
      
      {/* Hero Section */}
      <section className="gradient-subtle py-20 md:py-32">
        <div className="container mx-auto px-4">
          <div className="max-w-3xl mx-auto text-center space-y-6">
            <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-primary/10 text-primary text-sm font-medium mb-4">
              <Shield className="h-4 w-4" />
              Private & Confidential
            </div>
            
            <h1 className="text-5xl md:text-6xl font-bold leading-tight">
              Understand Your Mental Health
            </h1>
            
            <p className="text-xl text-muted-foreground leading-relaxed">
              A compassionate self-screening tool to help you understand brain-related symptoms. 
              Take validated assessments, chat with an AI assistant, and find professional support.
            </p>
            
            <div className="flex flex-col sm:flex-row gap-4 justify-center pt-6">
              <Link to="/signup">
                <Button size="lg" className="gradient-primary text-white shadow-medium hover:shadow-large transition-smooth">
                  Get Started Free
                </Button>
              </Link>
              <Link to="/chat">
                <Button size="lg" variant="outline">
                  Try Chat Demo
                </Button>
              </Link>
            </div>
            
            <p className="text-sm text-muted-foreground pt-4">
              ⚠️ This is a screening tool, not a clinical diagnosis. Always consult healthcare professionals.
            </p>
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section className="py-20">
        <div className="container mx-auto px-4">
          <div className="text-center max-w-2xl mx-auto mb-16">
            <h2 className="text-3xl md:text-4xl font-bold mb-4">
              Comprehensive Mental Health Support
            </h2>
            <p className="text-lg text-muted-foreground">
              Evidence-based tools to help you understand and manage your mental wellbeing
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            <Card className="p-6 hover:shadow-medium transition-smooth">
              <div className="w-12 h-12 rounded-lg bg-primary/10 flex items-center justify-center mb-4">
                <MessageCircle className="h-6 w-6 text-primary" />
              </div>
              <h3 className="text-xl font-semibold mb-2">AI Chat Assistant</h3>
              <p className="text-muted-foreground">
                Have empathetic conversations about your symptoms with our trained AI assistant. Get personalized insights and recommendations.
              </p>
            </Card>

            <Card className="p-6 hover:shadow-medium transition-smooth">
              <div className="w-12 h-12 rounded-lg bg-accent/10 flex items-center justify-center mb-4">
                <ClipboardList className="h-6 w-6 text-accent" />
              </div>
              <h3 className="text-xl font-semibold mb-2">Validated Tests</h3>
              <p className="text-muted-foreground">
                Take clinically validated screening tests for ADHD, depression, and other conditions. Receive instant, detailed results.
              </p>
            </Card>

            <Card className="p-6 hover:shadow-medium transition-smooth">
              <div className="w-12 h-12 rounded-lg bg-info/10 flex items-center justify-center mb-4">
                <BookOpen className="h-6 w-6 text-info" />
              </div>
              <h3 className="text-xl font-semibold mb-2">Learn & Understand</h3>
              <p className="text-muted-foreground">
                Access curated educational resources, articles, and videos about mental health conditions and coping strategies.
              </p>
            </Card>

            <Card className="p-6 hover:shadow-medium transition-smooth">
              <div className="w-12 h-12 rounded-lg bg-success/10 flex items-center justify-center mb-4">
                <Users className="h-6 w-6 text-success" />
              </div>
              <h3 className="text-xl font-semibold mb-2">Find Professionals</h3>
              <p className="text-muted-foreground">
                Locate nearby psychiatrists and psychologists. Get contact information and specialties to find the right help.
              </p>
            </Card>

            <Card className="p-6 hover:shadow-medium transition-smooth">
              <div className="w-12 h-12 rounded-lg bg-warning/10 flex items-center justify-center mb-4">
                <Brain className="h-6 w-6 text-warning" />
              </div>
              <h3 className="text-xl font-semibold mb-2">Symptom Analysis</h3>
              <p className="text-muted-foreground">
                Describe your symptoms freely and get AI-powered analysis with potential conditions and next steps to consider.
              </p>
            </Card>

            <Card className="p-6 hover:shadow-medium transition-smooth">
              <div className="w-12 h-12 rounded-lg bg-destructive/10 flex items-center justify-center mb-4">
                <Shield className="h-6 w-6 text-destructive" />
              </div>
              <h3 className="text-xl font-semibold mb-2">Private & Secure</h3>
              <p className="text-muted-foreground">
                Your data is encrypted and private. We prioritize your confidentiality and never share your personal information.
              </p>
            </Card>
          </div>
        </div>
      </section>

      {/* How It Works */}
      <section className="py-20 gradient-subtle">
        <div className="container mx-auto px-4">
          <div className="text-center max-w-2xl mx-auto mb-16">
            <h2 className="text-3xl md:text-4xl font-bold mb-4">
              How NeuroAid Works
            </h2>
            <p className="text-lg text-muted-foreground">
              Simple steps to better understand your mental health
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-8 max-w-4xl mx-auto">
            <div className="text-center space-y-4">
              <div className="w-16 h-16 rounded-full bg-primary text-white flex items-center justify-center mx-auto text-2xl font-bold">
                1
              </div>
              <h3 className="text-xl font-semibold">Create Your Account</h3>
              <p className="text-muted-foreground">
                Sign up securely in seconds. Your privacy is our top priority.
              </p>
            </div>

            <div className="text-center space-y-4">
              <div className="w-16 h-16 rounded-full bg-primary text-white flex items-center justify-center mx-auto text-2xl font-bold">
                2
              </div>
              <h3 className="text-xl font-semibold">Take Assessments</h3>
              <p className="text-muted-foreground">
                Complete validated tests or chat with our AI about your symptoms.
              </p>
            </div>

            <div className="text-center space-y-4">
              <div className="w-16 h-16 rounded-full bg-primary text-white flex items-center justify-center mx-auto text-2xl font-bold">
                3
              </div>
              <h3 className="text-xl font-semibold">Get Insights & Help</h3>
              <p className="text-muted-foreground">
                Review your results, learn more, and connect with professionals if needed.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-20">
        <div className="container mx-auto px-4">
          <Card className="gradient-primary text-white p-12 text-center shadow-large">
            <h2 className="text-3xl md:text-4xl font-bold mb-4">
              Ready to Take the First Step?
            </h2>
            <p className="text-lg mb-8 opacity-90 max-w-2xl mx-auto">
              Join thousands who have gained clarity about their mental health. 
              Start your journey to better understanding today.
            </p>
            <Link to="/signup">
              <Button size="lg" variant="secondary" className="shadow-medium">
                Start Free Assessment
              </Button>
            </Link>
          </Card>
        </div>
      </section>

      <Footer />
    </div>
  );
};

export default Landing;
