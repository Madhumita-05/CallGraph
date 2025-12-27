// src/main.jsx
import React, { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import Dashboard from "./dashboard.jsx";
import "./index.css";

function Root() {
  const [hasError, setHasError] = React.useState(false);
  const [errorInfo, setErrorInfo] = React.useState(null);

  React.useEffect(() => {
    function onError(event) {
      setHasError(true);
      setErrorInfo(event?.error?.message || event?.message || "Unknown error");
    }
    window.addEventListener("error", onError);
    return () => window.removeEventListener("error", onError);
  }, []);

  if (hasError) {
    return (
      <div className="app-shell">
        <header className="app-header">
          <div className="logo-block">
            <span className="logo-mark">CT</span>
            <div className="logo-text">
              <span className="logo-title">CT-OSINT</span>
              <span className="logo-subtitle">Threat Console</span>
            </div>
          </div>
          <div className="header-meta">
            <span className="chip chip-warn">UI Error</span>
          </div>
        </header>

        <main className="app-main grid-2cols">
          <section className="card card-alert">
            <div className="card-header">
              <h2 className="card-title">Something went wrong</h2>
              <span className="pill pill-low">Client only</span>
            </div>
            <p className="card-description">
              The dashboard hit a runtime error. Refresh the page and try again.
            </p>
            {errorInfo && (
              <pre className="code-block small">
                {String(errorInfo)}
              </pre>
            )}
          </section>
        </main>
      </div>
    );
  }

  return <Dashboard />;
}

const container = document.getElementById("root");
const root = createRoot(container);

root.render(
  <StrictMode>
    <Root />
  </StrictMode>
);
