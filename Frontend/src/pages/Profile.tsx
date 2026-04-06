import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Header } from "@/components/Header";
import { Footer } from "@/components/Footer";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { User, Mail, Calendar, Shield } from "lucide-react";
import { api } from "@/lib/api";
import { toast } from "sonner";

const Profile = () => {
  const navigate = useNavigate();
  const [user, setUser] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem('neuroaid_token');
    if (!token) {
      navigate('/login');
      return;
    }

    const fetchUser = async () => {
      try {
        const userData = await api.getMe();
        setUser(userData);
      } catch (error) {
        toast.error("Failed to load profile");
        navigate('/login');
      } finally {
        setLoading(false);
      }
    };

    fetchUser();
  }, [navigate]);

  const handleDeleteAccount = () => {
    if (confirm("Are you sure you want to delete your account? This action cannot be undone.")) {
      toast.error("Account deletion not implemented in backend yet");
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-pulse text-primary">Loading profile...</div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex flex-col">
      <Header />
      
      <main className="flex-1 container mx-auto px-4 py-8">
        <div className="max-w-3xl mx-auto">
          <div className="mb-8">
            <h1 className="text-3xl font-bold mb-2">Your Profile</h1>
            <p className="text-muted-foreground">Manage your account information and settings</p>
          </div>

          {/* Profile Info */}
          <Card className="p-6 mb-6">
            <div className="flex items-start gap-6">
              <div className="w-20 h-20 rounded-full bg-gradient-primary flex items-center justify-center text-white text-2xl font-bold flex-shrink-0">
                {user?.display_name?.charAt(0)?.toUpperCase() || 'U'}
              </div>

              <div className="flex-1 space-y-4">
                <div>
                  <div className="flex items-center gap-2 text-muted-foreground mb-1">
                    <User className="h-4 w-4" />
                    <span className="text-sm">Display Name</span>
                  </div>
                  <p className="text-lg font-medium">{user?.display_name || 'Not set'}</p>
                </div>

                <div>
                  <div className="flex items-center gap-2 text-muted-foreground mb-1">
                    <Mail className="h-4 w-4" />
                    <span className="text-sm">Email Address</span>
                  </div>
                  <p className="text-lg font-medium">{user?.email}</p>
                </div>

                <div>
                  <div className="flex items-center gap-2 text-muted-foreground mb-1">
                    <Shield className="h-4 w-4" />
                    <span className="text-sm">Account Type</span>
                  </div>
                  <p className="text-lg font-medium capitalize">{user?.role || 'User'}</p>
                </div>
              </div>
            </div>
          </Card>

          {/* Data & Privacy */}
          <Card className="p-6 mb-6">
            <h3 className="text-xl font-semibold mb-4">Data & Privacy</h3>
            <div className="space-y-4">
              <div className="flex items-start gap-3">
                <Shield className="h-5 w-5 text-primary flex-shrink-0 mt-0.5" />
                <div className="flex-1">
                  <h4 className="font-medium mb-1">Your Data is Secure</h4>
                  <p className="text-sm text-muted-foreground">
                    All your conversations, assessments, and personal information are encrypted and stored securely. 
                    We never share your data with third parties.
                  </p>
                </div>
              </div>

              <div className="flex items-start gap-3">
                <Calendar className="h-5 w-5 text-primary flex-shrink-0 mt-0.5" />
                <div className="flex-1">
                  <h4 className="font-medium mb-1">Data Retention</h4>
                  <p className="text-sm text-muted-foreground">
                    Your assessment history and chat logs are kept to help track your progress over time. 
                    You can request deletion at any time.
                  </p>
                </div>
              </div>
            </div>
          </Card>

          {/* Actions */}
          <Card className="p-6">
            <h3 className="text-xl font-semibold mb-4">Account Actions</h3>
            <div className="space-y-3">
              <Button variant="outline" className="w-full justify-start" onClick={() => navigate('/reports')}>
                View My Assessment History
              </Button>
              <Button variant="outline" className="w-full justify-start" onClick={() => toast.info("Export feature coming soon")}>
                Export My Data
              </Button>
              <Button 
                variant="destructive" 
                className="w-full justify-start"
                onClick={handleDeleteAccount}
              >
                Delete Account
              </Button>
            </div>
          </Card>
        </div>
      </main>

      <Footer />
    </div>
  );
};

export default Profile;
