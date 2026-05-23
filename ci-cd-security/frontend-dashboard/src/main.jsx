import React from "react";
import { createRoot } from "react-dom/client";
import "./styles.css";
import App from "./App.jsx";
import {
  Router,
  ThemeProvider,
  AuthProvider,
  SettingsProvider,
} from "./context/AppContext.jsx";
import { DataProvider } from "./context/DataContext.jsx";
function Root() {
  return (
    <Router>
      <ThemeProvider>
        <AuthProvider>
          <SettingsProvider>
            <DataProvider>
              <App />
            </DataProvider>
          </SettingsProvider>
        </AuthProvider>
      </ThemeProvider>
    </Router>
  );
}
createRoot(document.getElementById("root")).render(<Root />);
