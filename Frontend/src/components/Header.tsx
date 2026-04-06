import { Link } from "react-router-dom";
import { Brain, Menu, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useState } from "react";

export const Header = () => {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const token = localStorage.getItem('neuroaid_token');

  const handleLogout = () => {
    localStorage.removeItem('neuroaid_token');
    window.location.href = '/';
  };

  return (
    <header className="border-b bg-card/50 backdrop-blur-sm sticky top-0 z-50">
      <div className="container mx-auto px-4">
        <div className="flex items-center justify-between h-16">
          <Link to="/" className="flex items-center gap-2 transition-smooth hover:opacity-80">
            <Brain className="h-8 w-8 text-primary" />
            <span className="text-xl font-bold bg-gradient-to-r from-primary to-accent bg-clip-text text-transparent">
              NeuroAid
            </span>
          </Link>

          {/* Desktop Navigation */}
          <nav className="hidden md:flex items-center gap-6">
            <Link to="/dashboard" className="text-sm font-medium hover:text-primary transition-base">
              Dashboard
            </Link>
            <Link to="/chat" className="text-sm font-medium hover:text-primary transition-base">
              Chat
            </Link>
            <Link to="/tests" className="text-sm font-medium hover:text-primary transition-base">
              Tests
            </Link>
            <Link to="/learn" className="text-sm font-medium hover:text-primary transition-base">
              Learn
            </Link>
            <Link to="/consultants" className="text-sm font-medium hover:text-primary transition-base">
              Find Help
            </Link>
          </nav>

          {/* Auth Buttons */}
          <div className="hidden md:flex items-center gap-3">
            {token ? (
              <>
                <Link to="/profile">
                  <Button variant="ghost" size="sm">Profile</Button>
                </Link>
                <Button variant="outline" size="sm" onClick={handleLogout}>
                  Logout
                </Button>
              </>
            ) : (
              <>
                <Link to="/login">
                  <Button variant="ghost" size="sm">Login</Button>
                </Link>
                <Link to="/signup">
                  <Button size="sm">Sign Up</Button>
                </Link>
              </>
            )}
          </div>

          {/* Mobile Menu Button */}
          <button
            className="md:hidden p-2"
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            aria-label="Toggle menu"
          >
            {mobileMenuOpen ? <X className="h-6 w-6" /> : <Menu className="h-6 w-6" />}
          </button>
        </div>

        {/* Mobile Menu */}
        {mobileMenuOpen && (
          <div className="md:hidden pb-4 pt-2 space-y-2">
            <Link
              to="/dashboard"
              className="block py-2 text-sm font-medium hover:text-primary transition-base"
              onClick={() => setMobileMenuOpen(false)}
            >
              Dashboard
            </Link>
            <Link
              to="/chat"
              className="block py-2 text-sm font-medium hover:text-primary transition-base"
              onClick={() => setMobileMenuOpen(false)}
            >
              Chat
            </Link>
            <Link
              to="/tests"
              className="block py-2 text-sm font-medium hover:text-primary transition-base"
              onClick={() => setMobileMenuOpen(false)}
            >
              Tests
            </Link>
            <Link
              to="/learn"
              className="block py-2 text-sm font-medium hover:text-primary transition-base"
              onClick={() => setMobileMenuOpen(false)}
            >
              Learn
            </Link>
            <Link
              to="/consultants"
              className="block py-2 text-sm font-medium hover:text-primary transition-base"
              onClick={() => setMobileMenuOpen(false)}
            >
              Find Help
            </Link>
            <div className="pt-2 space-y-2">
              {token ? (
                <>
                  <Link to="/profile" onClick={() => setMobileMenuOpen(false)}>
                    <Button variant="ghost" size="sm" className="w-full">
                      Profile
                    </Button>
                  </Link>
                  <Button
                    variant="outline"
                    size="sm"
                    className="w-full"
                    onClick={() => {
                      handleLogout();
                      setMobileMenuOpen(false);
                    }}
                  >
                    Logout
                  </Button>
                </>
              ) : (
                <>
                  <Link to="/login" onClick={() => setMobileMenuOpen(false)}>
                    <Button variant="ghost" size="sm" className="w-full">
                      Login
                    </Button>
                  </Link>
                  <Link to="/signup" onClick={() => setMobileMenuOpen(false)}>
                    <Button size="sm" className="w-full">
                      Sign Up
                    </Button>
                  </Link>
                </>
              )}
            </div>
          </div>
        )}
      </div>
    </header>
  );
};
