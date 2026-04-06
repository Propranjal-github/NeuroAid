import { Link } from "react-router-dom";
import { Brain } from "lucide-react";

export const Footer = () => {
  return (
    <footer className="border-t bg-card/30 mt-20">
      <div className="container mx-auto px-4 py-12">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
          <div className="space-y-4">
            <div className="flex items-center gap-2">
              <Brain className="h-6 w-6 text-primary" />
              <span className="font-bold text-lg">NeuroAid</span>
            </div>
            <p className="text-sm text-muted-foreground">
              Mental health screening and support platform. Not a replacement for professional diagnosis.
            </p>
          </div>

          <div>
            <h3 className="font-semibold mb-4">Quick Links</h3>
            <ul className="space-y-2 text-sm">
              <li>
                <Link to="/dashboard" className="text-muted-foreground hover:text-primary transition-base">
                  Dashboard
                </Link>
              </li>
              <li>
                <Link to="/tests" className="text-muted-foreground hover:text-primary transition-base">
                  Take a Test
                </Link>
              </li>
              <li>
                <Link to="/learn" className="text-muted-foreground hover:text-primary transition-base">
                  Learn More
                </Link>
              </li>
            </ul>
          </div>

          <div>
            <h3 className="font-semibold mb-4">Support</h3>
            <ul className="space-y-2 text-sm">
              <li>
                <Link to="/contact" className="text-muted-foreground hover:text-primary transition-base">
                  Contact Us
                </Link>
              </li>
              <li>
                <Link to="/consultants" className="text-muted-foreground hover:text-primary transition-base">
                  Find a Professional
                </Link>
              </li>
            </ul>
          </div>

          <div>
            <h3 className="font-semibold mb-4">Crisis Resources</h3>
            <ul className="space-y-2 text-sm text-muted-foreground">
              <li>National Suicide Hotline: 988</li>
              <li>Crisis Text Line: Text HOME to 741741</li>
              <li>SAMHSA: 1-800-662-4357</li>
            </ul>
          </div>
        </div>

        <div className="border-t mt-8 pt-8 text-center text-sm text-muted-foreground">
          <p>© 2025 NeuroAid. This is a screening tool, not a diagnostic service.</p>
          <div className="mt-2 space-x-4">
            <Link to="/privacy" className="hover:text-primary transition-base">Privacy Policy</Link>
            <Link to="/terms" className="hover:text-primary transition-base">Terms of Service</Link>
          </div>
        </div>
      </div>
    </footer>
  );
};
