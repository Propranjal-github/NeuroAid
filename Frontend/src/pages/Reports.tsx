import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Header } from "@/components/Header";
import { Footer } from "@/components/Footer";
import { Card } from "@/components/ui/card";
import { FileText, Calendar, Download, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import { toast } from "sonner";
import { jsPDF } from "jspdf";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

interface ReportData {
  id: number;
  title: string;
  date: string;
  score: number;
  type: string;
  interpretation?: string;
  confidence?: number;
}

const Reports = () => {
  const navigate = useNavigate();
  const [reports, setReports] = useState<ReportData[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedReport, setSelectedReport] = useState<ReportData | null>(null);

  useEffect(() => {
    const token = localStorage.getItem('neuroaid_token');
    if (!token) {
      toast.error("Please log in to view reports");
      navigate('/login');
      return;
    }
    
    fetchReports();
  }, [navigate]);

  const fetchReports = async () => {
    try {
      const response = await api.getReports();
      setReports(response.reports || []);
    } catch (error) {
      toast.error("Failed to fetch reports");
    } finally {
      setLoading(false);
    }
  };

  const handleDownload = (report: ReportData) => {
    try {
      const doc = new jsPDF();
      
      const margin = 20;
      let y = 20;

      doc.setFont("helvetica", "bold");
      doc.setFontSize(22);
      doc.setTextColor(40, 40, 40);
      doc.text(report.title.toUpperCase(), margin, y);
      y += 15;

      doc.setFont("helvetica", "normal");
      doc.setFontSize(12);
      doc.setTextColor(100, 100, 100);
      doc.text(`Date: ${new Date(report.date).toLocaleDateString()}`, margin, y);
      y += 8;
      doc.text(`Test Type: ${report.type}`, margin, y);
      y += 8;
      
      doc.setTextColor(20, 20, 20);
      doc.setFontSize(14);
      doc.text(`Score: ${report.score}`, margin, y);
      y += 8;
      doc.text(`Confidence: ${report.confidence ? (report.confidence * 100).toFixed(0) : 'N/A'}%`, margin, y);
      y += 15;

      doc.setFont("helvetica", "bold");
      doc.setFontSize(16);
      doc.text("RESULTS & INTERPRETATION", margin, y);
      y += 10;

      doc.setFont("helvetica", "normal");
      doc.setFontSize(12);
      doc.setTextColor(60, 60, 60);
      
      const interpretation = report.interpretation || "No detailed interpretation available.";
      const splitText = doc.splitTextToSize(interpretation, 170); // Wrap at 170 width
      doc.text(splitText, margin, y);
      
      doc.setFontSize(10);
      doc.setTextColor(150, 150, 150);
      doc.text("* Note: This is an automated screening report and does not constitute a medical diagnosis.", margin, 280);

      doc.save(`NeuroAid_${report.type.replace(/\s+/g, "_")}_Report.pdf`);
      toast.success("Report downloaded successfully");
    } catch (err) {
      toast.error("Error creating PDF file");
    }
  };

  return (
    <div className="min-h-screen flex flex-col bg-background">
      <Header />
      
      <main className="flex-1 container mx-auto px-4 py-8">
        <div className="max-w-4xl mx-auto">
          <div className="mb-8">
            <h1 className="text-3xl font-bold mb-2">Your Assessment Reports</h1>
            <p className="text-muted-foreground">
              Access your assessment history and download reports
            </p>
          </div>

          {loading ? (
            <div className="flex justify-center my-12">
              <Loader2 className="h-8 w-8 animate-spin text-primary" />
            </div>
          ) : reports.length === 0 ? (
            <Card className="p-12 text-center">
              <FileText className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
              <h3 className="text-lg font-semibold mb-2">No Reports Yet</h3>
              <p className="text-muted-foreground mb-6">
                Complete an assessment or chat with our AI to generate your first report
              </p>
              <Button onClick={() => navigate('/tests')}>Take an Assessment</Button>
            </Card>
          ) : (
            <div className="space-y-4">
              {reports.map((report) => (
                <Card key={report.id} className="p-6 hover:shadow-md transition-all">
                  <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
                    <div className="flex items-start gap-4">
                      <div className="w-12 h-12 rounded-lg bg-primary/10 flex items-center justify-center flex-shrink-0">
                        <FileText className="h-6 w-6 text-primary" />
                      </div>
                      <div>
                        <h3 className="text-lg font-semibold mb-1">{report.title}</h3>
                        <div className="flex items-center gap-4 text-sm text-muted-foreground">
                          <div className="flex items-center gap-1">
                            <Calendar className="h-3 w-3" />
                            <span>{new Date(report.date).toLocaleDateString()}</span>
                          </div>
                          <span>Score: {report.score}</span>
                          <span className="px-2 py-1 rounded-full bg-muted text-xs">
                            {report.type}
                          </span>
                        </div>
                      </div>
                    </div>

                    <div className="flex gap-2">
                      <Button variant="outline" size="sm" onClick={() => setSelectedReport(report)}>
                        View Report
                      </Button>
                      <Button variant="ghost" size="sm" onClick={() => handleDownload(report)}>
                        <Download className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                </Card>
              ))}
            </div>
          )}
        </div>
      </main>

      <Footer />

      {/* View Report Dialog Modal */}
      <Dialog open={!!selectedReport} onOpenChange={() => setSelectedReport(null)}>
        <DialogContent className="sm:max-w-md max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>{selectedReport?.title}</DialogTitle>
            <DialogDescription>
              Completed on {selectedReport ? new Date(selectedReport.date).toLocaleDateString() : ""}
            </DialogDescription>
          </DialogHeader>
          {selectedReport && (
            <div className="space-y-4 py-4">
              <div className="grid grid-cols-2 gap-4 bg-muted/30 p-4 rounded-lg">
                <div>
                  <p className="text-sm text-muted-foreground">Score</p>
                  <p className="font-semibold text-lg">{selectedReport.score}</p>
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Confidence</p>
                  <p className="font-semibold text-lg">
                    {selectedReport.confidence ? (selectedReport.confidence * 100).toFixed(0) : "N/A"}%
                  </p>
                </div>
                <div className="col-span-2">
                  <p className="text-sm text-muted-foreground">Assessment Type</p>
                  <p className="font-medium">{selectedReport.type}</p>
                </div>
              </div>

              <div>
                <h4 className="font-semibold mb-2">Interpretation & Analysis</h4>
                <div className="text-sm text-muted-foreground whitespace-pre-wrap leading-relaxed border p-4 rounded-lg bg-card">
                  {selectedReport.interpretation || "No interpretation provided."}
                </div>
              </div>

              <p className="text-xs text-muted-foreground text-center mt-4">
                This is a screening analysis, not a medical diagnosis.
              </p>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
};

export default Reports;
