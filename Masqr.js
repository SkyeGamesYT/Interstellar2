import fetch from "node-fetch";

const LICENSE_SERVER_URL = "https://masqr.gointerstellar.app/validate?license=";

function customAuthMiddleware(req, res, next) {
  // Skip non-login routes if needed, or apply globally
  // For now, apply globally to all requests

  // If user already authenticated (cookie present), continue
  if (req.cookies["authcheck"]) {
    return next();
  }

  // Extract Authorization header
  const authheader = req.headers.authorization;
  if (!authheader || !authheader.startsWith("Basic ")) {
    res.setHeader("WWW-Authenticate", "Basic");
    return res.status(401).send("Authentication required");
  }

  // Decode username:password
  const [username, password] = Buffer.from(authheader.split(" ")[1], "base64")
    .toString()
    .split(":");

  if (!username || !password) {
    res.setHeader("WWW-Authenticate", "Basic");
    return res.status(401).send("Invalid authentication");
  }

  // Extract HWID header, fallback to UNKNOWN_HWID
  const hwid = req.headers["x-hwid"] || "UNKNOWN_HWID";

  // Optionally, check username against config.users (basic whitelist)
  // Or skip this if license server validates everything

  // Call license server to validate license+hwid
  fetch(LICENSE_SERVER_URL + encodeURIComponent(password) + "&host=" + req.headers.host + "&hwid=" + encodeURIComponent(hwid))
    .then(r => r.json())
    .then(data => {
      if (data.status === "License valid") {
        // Set auth cookie for persistent login
        res.cookie("authcheck", "true", {
          expires: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000), // 1 year
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
        });

        console.log(`User ${username} logged in with HWID ${hwid}`);

        // Redirect or continue
        return res.send("<script>window.location.reload()</script>");
      } else {
        res.setHeader("WWW-Authenticate", "Basic");
        return res.status(401).send("Invalid license");
      }
    })
    .catch(err => {
      console.error("License validation error:", err);
      res.status(500).send("Server error");
    });
}

export default customAuthMiddleware;
