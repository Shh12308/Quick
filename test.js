import express from "express";

const app = express();
const PORT = process.env.PORT || 8443;

app.get("/", (req, res) => res.send("OK"));
app.get("/api/health", (req, res) => res.json({ status: "ok" }));

app.listen(PORT, "0.0.0.0", () => {
  console.log("Server running on", PORT);
});
