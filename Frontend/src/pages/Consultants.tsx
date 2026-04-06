import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { Header } from "@/components/Header";
import { Footer } from "@/components/Footer";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { MapPin, Phone, Navigation, Loader2 } from "lucide-react";
import { api } from "@/lib/api";
import { toast } from "sonner";

const Consultants = () => {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  const [consultants, setConsultants] = useState<any[]>([]);
  const [location, setLocation] = useState<{ lat: number; lng: number } | null>(null);
  const [searchQuery, setSearchQuery] = useState("psychiatrist");

  useEffect(() => {
    const token = localStorage.getItem('neuroaid_token');
    if (!token) {
      toast.error("Please log in to find consultants");
      navigate('/login');
    }
  }, [navigate]);

  const requestLocation = () => {
    setLoading(true);
    if ('geolocation' in navigator) {
      navigator.geolocation.getCurrentPosition(
        async (position) => {
          const coords = {
            lat: position.coords.latitude,
            lng: position.coords.longitude,
          };
          setLocation(coords);
          await fetchConsultants(coords);
        },
        (error) => {
          toast.error("Failed to get location. Please enable location services.");
          setLoading(false);
        }
      );
    } else {
      toast.error("Geolocation is not supported by your browser");
      setLoading(false);
    }
  };

  const fetchConsultants = async (coords: { lat: number; lng: number }) => {
    try {
      const data = await api.getConsultants(coords.lat, coords.lng, searchQuery);
      setConsultants(data.results);
    } catch (error) {
      toast.error("Failed to fetch consultants");
    } finally {
      setLoading(false);
    }
  };

  const handleSearch = () => {
    if (location) {
      setLoading(true);
      fetchConsultants(location);
    } else {
      toast.error("Please enable location first");
    }
  };

  return (
    <div className="min-h-screen flex flex-col">
      <Header />
      
      <main className="flex-1 container mx-auto px-4 py-8">
        <div className="max-w-5xl mx-auto">
          <div className="mb-8">
            <h1 className="text-3xl md:text-4xl font-bold mb-2">Find Mental Health Professionals</h1>
            <p className="text-muted-foreground text-lg">
              Locate nearby psychiatrists and psychologists to get professional help
            </p>
          </div>

          {/* Search Controls */}
          <Card className="p-6 mb-8">
            <div className="space-y-4">
              <div className="flex gap-4">
                <Input
                  placeholder="Search for psychiatrist, psychologist, therapist..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="flex-1"
                />
                <Button onClick={handleSearch} disabled={!location || loading}>
                  {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : "Search"}
                </Button>
              </div>

              {!location && (
                <Button onClick={requestLocation} variant="outline" className="w-full" disabled={loading}>
                  <Navigation className="h-4 w-4 mr-2" />
                  {loading ? "Getting location..." : "Enable Location"}
                </Button>
              )}

              {location && (
                <p className="text-sm text-muted-foreground text-center">
                  📍 Location enabled • Searching within 5km radius
                </p>
              )}
            </div>
          </Card>

          {/* Results */}
          {consultants.length === 0 && !loading && location && (
            <Card className="p-12 text-center">
              <p className="text-muted-foreground">
                No results found. Try adjusting your search or location.
              </p>
            </Card>
          )}

          {consultants.length > 0 && (
            <div className="space-y-4">
              {consultants.map((consultant, index) => (
                <Card key={index} className="p-6 hover:shadow-medium transition-smooth">
                  <div className="flex flex-col md:flex-row md:items-start md:justify-between gap-4">
                    <div className="flex-1">
                      <h3 className="text-xl font-semibold mb-2">{consultant.name}</h3>
                      
                      {consultant.vicinity && (
                        <div className="flex items-start gap-2 text-sm text-muted-foreground mb-2">
                          <MapPin className="h-4 w-4 flex-shrink-0 mt-0.5" />
                          <span>{consultant.vicinity}</span>
                        </div>
                      )}

                      {consultant.types && (
                        <div className="flex flex-wrap gap-2 mt-3">
                          {consultant.types.slice(0, 3).map((type: string) => (
                            <span
                              key={type}
                              className="text-xs px-2 py-1 rounded-full bg-primary/10 text-primary"
                            >
                              {type.replace(/_/g, ' ')}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>

                    <div className="flex flex-col gap-2">
                      {consultant.place_id && (
                        <a
                          href={`https://www.google.com/maps/search/?api=1&query=Google&query_place_id=${consultant.place_id}`}
                          target="_blank"
                          rel="noopener noreferrer"
                        >
                          <Button variant="outline" size="sm" className="w-full">
                            <MapPin className="h-4 w-4 mr-2" />
                            View on Map
                          </Button>
                        </a>
                      )}
                    </div>
                  </div>
                </Card>
              ))}
            </div>
          )}

          {/* Crisis Resources */}
          <Card className="mt-8 p-6 border-destructive/30 bg-destructive/5">
            <h3 className="font-semibold mb-3">Crisis Resources - Available 24/7</h3>
            <div className="space-y-2 text-sm">
              <div className="flex items-center gap-2">
                <Phone className="h-4 w-4" />
                <span><strong>National Suicide Hotline:</strong> Call or text 988</span>
              </div>
              <div className="flex items-center gap-2">
                <Phone className="h-4 w-4" />
                <span><strong>Crisis Text Line:</strong> Text HOME to 741741</span>
              </div>
              <div className="flex items-center gap-2">
                <Phone className="h-4 w-4" />
                <span><strong>SAMHSA Helpline:</strong> 1-800-662-4357</span>
              </div>
            </div>
          </Card>
        </div>
      </main>

      <Footer />
    </div>
  );
};

export default Consultants;
