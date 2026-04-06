import { Link } from "react-router-dom";
import { Header } from "@/components/Header";
import { Footer } from "@/components/Footer";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { ClipboardList, Clock, CheckCircle } from "lucide-react";

const Tests = () => {
  const tests = [
    {
      id: "ADHD_ASRS6",
      title: "ADHD Screening (ASRS-6)",
      description: "A 6-question screening tool for adult ADHD symptoms based on organization, attention, and focus issues.",
      duration: "2-3 minutes",
      questions: 6,
      path: "/test/adhd",
    },
    {
      id: "PHQ2",
      title: "Depression Screening (PHQ-2)",
      description: "A brief 2-question screening for depressive symptoms. If positive, a full PHQ-9 assessment is recommended.",
      duration: "1 minute",
      questions: 2,
      path: "/test/depression",
    },
  ];

  return (
    <div className="min-h-screen flex flex-col">
      <Header />
      
      <main className="flex-1 container mx-auto px-4 py-8">
        <div className="max-w-4xl mx-auto">
          <div className="mb-8">
            <h1 className="text-3xl md:text-4xl font-bold mb-2">Mental Health Assessments</h1>
            <p className="text-muted-foreground text-lg">
              Take validated screening tests to better understand your symptoms. Remember, these are screening tools, not diagnoses.
            </p>
          </div>

          {/* Important Notice */}
          <Card className="p-6 border-warning/50 bg-warning/5 mb-8">
            <div className="flex gap-3">
              <div className="text-warning flex-shrink-0">⚠️</div>
              <div>
                <h3 className="font-semibold mb-2">Before You Begin</h3>
                <ul className="text-sm text-muted-foreground space-y-1 list-disc list-inside">
                  <li>These tests are screening tools, not clinical diagnoses</li>
                  <li>Answer honestly for the most accurate results</li>
                  <li>Your responses are private and encrypted</li>
                  <li>High scores suggest you should consult a mental health professional</li>
                </ul>
              </div>
            </div>
          </Card>

          {/* Test Cards */}
          <div className="space-y-6">
            {tests.map((test) => (
              <Card key={test.id} className="p-6 hover:shadow-medium transition-smooth">
                <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
                  <div className="flex-1">
                    <div className="flex items-start gap-3 mb-3">
                      <div className="w-12 h-12 rounded-lg bg-primary/10 flex items-center justify-center flex-shrink-0">
                        <ClipboardList className="h-6 w-6 text-primary" />
                      </div>
                      <div>
                        <h3 className="text-xl font-semibold mb-1">{test.title}</h3>
                        <p className="text-sm text-muted-foreground">{test.description}</p>
                      </div>
                    </div>

                    <div className="flex flex-wrap gap-4 text-sm text-muted-foreground ml-15">
                      <div className="flex items-center gap-1">
                        <Clock className="h-4 w-4" />
                        <span>{test.duration}</span>
                      </div>
                      <div className="flex items-center gap-1">
                        <CheckCircle className="h-4 w-4" />
                        <span>{test.questions} questions</span>
                      </div>
                    </div>
                  </div>

                  <Link to={test.path}>
                    <Button size="lg" className="w-full md:w-auto">
                      Start Test
                    </Button>
                  </Link>
                </div>
              </Card>
            ))}
          </div>

          {/* Additional Info */}
          <Card className="mt-8 p-6 bg-muted/50">
            <h3 className="font-semibold mb-3">After Your Assessment</h3>
            <ul className="space-y-2 text-sm text-muted-foreground">
              <li>• You'll receive your score and interpretation immediately</li>
              <li>• Results will be saved to your account for future reference</li>
              <li>• You can generate a downloadable report to share with healthcare providers</li>
              <li>• Consider using our AI chat for personalized follow-up questions</li>
              <li>• Find local mental health professionals in our consultant directory</li>
            </ul>
          </Card>
        </div>
      </main>

      <Footer />
    </div>
  );
};

export default Tests;
