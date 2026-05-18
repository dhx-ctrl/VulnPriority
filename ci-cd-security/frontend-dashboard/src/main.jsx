import React from 'react';
import { createRoot } from 'react-dom/client';
import './styles.css';
import App from './App.jsx';
import { Router, ThemeProvider, AuthProvider, SettingsProvider } from './context/AppContext.jsx';
import { DataProvider } from './context/DataContext.jsx';

function Root() {
  return React.createElement(Router, null,
    React.createElement(ThemeProvider, null,
      React.createElement(AuthProvider, null,
        React.createElement(SettingsProvider, null,
          React.createElement(DataProvider, null,
            React.createElement(App, null),
          ),
        ),
      ),
    ),
  );
}

createRoot(document.getElementById('root')).render(React.createElement(Root, null));
