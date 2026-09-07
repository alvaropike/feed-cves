import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import FeedVulnerabilidades from "../FeedVulnerabilidades.jsx";

createRoot(document.getElementById("root")).render(
  <StrictMode>
    <FeedVulnerabilidades />
  </StrictMode>
);
