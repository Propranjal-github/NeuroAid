import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { Header } from "@/components/Header";
import { Footer } from "@/components/Footer";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { BookOpen, Video, FileText, Search, ExternalLink } from "lucide-react";
import { api } from "@/lib/api";
import { toast } from "sonner";

const Learn = () => {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [items, setItems] = useState<any[]>([]);
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedTag, setSelectedTag] = useState("adhd");

  useEffect(() => {
    const token = localStorage.getItem('neuroaid_token');
    if (!token) {
      toast.error("Please log in to access resources");
      navigate('/login');
      return;
    }

    const fetchContent = async () => {
      setLoading(true);
      setItems([]);
      try {
        const data = await api.getLearnContent(selectedTag);
        setItems(data.items);
      } catch (error) {
        toast.error("Failed to load resources");
      } finally {
        setLoading(false);
      }
    };

    fetchContent();
  }, [selectedTag, navigate]);

  const tags = ["adhd", "depression", "anxiety", "ocd", "coping", "therapy"];

  const filteredItems = items.filter(item =>
    item.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
    item.summary.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const getIcon = (type: string) => {
    switch (type) {
      case 'video': return <Video className="h-5 w-5" />;
      case 'article': return <FileText className="h-5 w-5" />;
      default: return <BookOpen className="h-5 w-5" />;
    }
  };

  return (
    <div className="min-h-screen flex flex-col">
      <Header />
      
      <main className="flex-1 container mx-auto px-4 py-8">
        <div className="max-w-6xl mx-auto">
          <div className="mb-8">
            <h1 className="text-3xl md:text-4xl font-bold mb-2">Educational Resources</h1>
            <p className="text-muted-foreground text-lg">
              Learn about mental health conditions, coping strategies, and treatment options
            </p>
          </div>

          {/* Search and Filters */}
          <div className="mb-8 space-y-4">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search resources..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-10"
              />
            </div>

            <div className="flex flex-wrap gap-2">
              {tags.map((tag) => (
                <Button
                  key={tag}
                  variant={selectedTag === tag ? "default" : "outline"}
                  size="sm"
                  onClick={() => setSelectedTag(tag)}
                  className="capitalize"
                >
                  {tag}
                </Button>
              ))}
            </div>
          </div>

          {/* Resources Grid */}
          {loading ? (
            <div className="text-center py-12">
              <div className="animate-pulse text-primary">Loading resources...</div>
            </div>
          ) : filteredItems.length === 0 ? (
            <Card className="p-12 text-center">
              <p className="text-muted-foreground">No resources found. Try a different search or tag.</p>
            </Card>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {filteredItems.map((item) => (
                <Card key={item.id} className="p-6 hover:shadow-medium transition-smooth flex flex-col">
                  <div className="flex items-start gap-3 mb-3">
                    <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center flex-shrink-0">
                      {getIcon(item.type)}
                    </div>
                    <div className="flex-1">
                      <div className="text-xs text-muted-foreground uppercase mb-1">{item.type}</div>
                      <h3 className="font-semibold leading-tight">{item.title}</h3>
                    </div>
                  </div>

                  <p className="text-sm text-muted-foreground mb-4 flex-1">{item.summary}</p>

                  <div className="flex flex-wrap gap-1 mb-4">
                    {item.tags?.map((tag: string) => (
                      <span
                        key={tag}
                        className="text-xs px-2 py-1 rounded-full bg-muted text-muted-foreground"
                      >
                        {tag}
                      </span>
                    ))}
                  </div>

                  <a href={item.url} target="_blank" rel="noopener noreferrer" className="w-full">
                    <Button variant="outline" size="sm" className="w-full">
                      <span>Read More</span>
                      <ExternalLink className="h-3 w-3 ml-2" />
                    </Button>
                  </a>
                </Card>
              ))}
            </div>
          )}
        </div>
      </main>

      <Footer />
    </div>
  );
};

export default Learn;
