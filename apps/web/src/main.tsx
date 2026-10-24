import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import Boot from "./components/Boot";
import { getToken } from "./lib/api";
import "./theme.css";

getToken(); // capture and scrub #token=… BEFORE the router reads location.hash

const qc = new QueryClient({ defaultOptions: { queries: { retry: 1, refetchOnWindowFocus: false } } });

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={qc}>
      <Boot>
        <App />
      </Boot>
    </QueryClientProvider>
  </StrictMode>,
);
