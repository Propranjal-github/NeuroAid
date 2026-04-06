import { useEffect } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { api } from "@/lib/api";
import { toast } from "sonner";
import { Brain, Loader2 } from "lucide-react";

const OAuthCallback = () => {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  useEffect(() => {
    const existingToken = api.getToken();
    if (existingToken) {
      navigate("/dashboard", { replace: true });
      return;
    }

    const token = searchParams.get("token");
    const error = searchParams.get("error");

    if (error) {
      toast.error(
        error === "link_required"
          ? "Account exists with this email. Please sign in to link your Google account."
          : error
      );
      navigate("/login", { replace: true });
      return;
    }

    if (token) {
      api.setToken(token);
      toast.success("Welcome!");
      navigate("/dashboard", { replace: true });
    } else {
      toast.error("Authentication failed. Please try again.");
      navigate("/login", { replace: true });
    }
  }, [searchParams, navigate]);

  return (
    <div className="min-h-screen gradient-subtle flex items-center justify-center">
      <div className="text-center">
        <Brain className="h-12 w-12 text-primary mx-auto mb-4 animate-pulse" />
        <Loader2 className="h-8 w-8 animate-spin text-primary mx-auto mb-4" />
        <p className="text-muted-foreground">Completing sign in...</p>
      </div>
    </div>
  );
};

export default OAuthCallback;
