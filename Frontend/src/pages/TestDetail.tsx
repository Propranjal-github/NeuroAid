import { useState, useEffect } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { Header } from "@/components/Header";
import { Footer } from "@/components/Footer";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Progress } from "@/components/ui/progress";
import { api } from "@/lib/api";
import { toast } from "sonner";

const TestDetail = () => {
  const { type } = useParams<{ type: string }>();
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [test, setTest] = useState<any>(null);
  const [answers, setAnswers] = useState<Record<string, number>>({});
  const [currentQuestion, setCurrentQuestion] = useState(0);

  useEffect(() => {
    const token = localStorage.getItem('neuroaid_token');
    if (!token) {
      toast.error("Please log in to take tests");
      navigate('/login');
      return;
    }

    const fetchTest = async () => {
      try {
        const testType = type === 'adhd' ? 'ADHD' : type === 'depression' ? 'PHQ2' : type;
        const data = await api.getTest(testType!);
        setTest(data);
      } catch (error) {
        toast.error("Failed to load test");
        navigate('/tests');
      } finally {
        setLoading(false);
      }
    };

    fetchTest();
  }, [type, navigate]);

  const handleSubmit = async () => {
    if (Object.keys(answers).length !== test?.questions.length) {
      toast.error("Please answer all questions");
      return;
    }

    setSubmitting(true);
    try {
      const result = await api.submitTest(test.type, answers);
      toast.success("Assessment completed!");
      navigate('/test-result', { state: { result } });
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Failed to submit test");
    } finally {
      setSubmitting(false);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-pulse text-primary">Loading test...</div>
      </div>
    );
  }

  if (!test) return null;

  const progress = (Object.keys(answers).length / test.questions.length) * 100;
  const currentQ = test.questions[currentQuestion];

  return (
    <div className="min-h-screen flex flex-col">
      <Header />
      
      <main className="flex-1 container mx-auto px-4 py-8">
        <div className="max-w-2xl mx-auto">
          <div className="mb-8">
            <h1 className="text-3xl font-bold mb-2">{test.type} Assessment</h1>
            <p className="text-muted-foreground">Question {currentQuestion + 1} of {test.questions.length}</p>
          </div>

          <Card className="p-6 mb-4">
            <Progress value={progress} className="mb-6" />

            <div className="space-y-6">
              <div>
                <h3 className="text-lg font-medium mb-4">{currentQ.text}</h3>
                <RadioGroup
                  value={answers[currentQ.id]?.toString() ?? ""}
                  onValueChange={(value) => setAnswers({ ...answers, [currentQ.id]: parseInt(value) })}
                >
                  <div className="space-y-3">
                    {[0, 1, 2, 3, 4].slice(0, test.type === 'PHQ2' ? 4 : 5).map((value) => (
                      <Label 
                        key={value} 
                        htmlFor={`${currentQ.id}-${value}`} 
                        className="flex items-center space-x-2 p-3 rounded-lg hover:bg-muted/50 cursor-pointer border border-transparent has-[:checked]:border-primary"
                      >
                        <RadioGroupItem value={value.toString()} id={`${currentQ.id}-${value}`} />
                        <span className="flex-1 font-normal text-base">
                          {value === 0 && "Never / Not at all"}
                          {value === 1 && "Rarely / Several days"}
                          {value === 2 && "Sometimes / More than half the days"}
                          {value === 3 && "Often / Nearly every day"}
                          {value === 4 && "Very often"}
                        </span>
                      </Label>
                    ))}
                  </div>
                </RadioGroup>
              </div>

              <div className="flex justify-between pt-4">
                <Button
                  variant="outline"
                  onClick={() => setCurrentQuestion(Math.max(0, currentQuestion - 1))}
                  disabled={currentQuestion === 0}
                >
                  Previous
                </Button>

                {currentQuestion < test.questions.length - 1 ? (
                  <Button
                    onClick={() => setCurrentQuestion(currentQuestion + 1)}
                    disabled={answers[currentQ.id] === undefined}
                  >
                    Next
                  </Button>
                ) : (
                  <Button
                    onClick={handleSubmit}
                    disabled={submitting || Object.keys(answers).length !== test.questions.length}
                  >
                    {submitting ? "Submitting..." : "Submit Assessment"}
                  </Button>
                )}
              </div>
            </div>
          </Card>

          <Card className="p-4 bg-muted/30">
            <p className="text-sm text-muted-foreground text-center">
              Your responses are private and will only be used to generate your assessment results
            </p>
          </Card>
        </div>
      </main>

      <Footer />
    </div>
  );
};

export default TestDetail;
