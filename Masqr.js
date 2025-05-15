import fs from "node:fs"
import path from "node:path"
import fetch from "node-fetch"

const LICENSE_SERVER_URL = "https://masqr.gointerstellar.app/validate?license="
const Fail = fs.readFileSync("Failed.html", "utf8")


export function setupMasqr(app) {
  app.use(async (req, res, next) => {
    if (req.url.includes("/ca/")) {
      next()
      return
    }

    const authheader = req.headers.authorization
    // Extract HWID from custom header (fallback to UNKNOWN_HWID)
    const hwid = req.headers["x-hwid"] || "UNKNOWN_HWID"

    if (req.cookies["authcheck"]) {
      console.log(`Auth cookie present, HWID: ${hwid}`)
      next()
      return
    }

    if (req.cookies["refreshcheck"] !== "true") {
      res.cookie("refreshcheck", "true", { maxAge: 10000 })
      MasqFail(req, res)
      return
    }

    if (!authheader) {
      res.setHeader("WWW-Authenticate", "Basic")
      res.status(401)
      MasqFail(req, res)
      return
    }

    const auth = Buffer.from(authheader.split(" ")[1], "base64").toString().split(":")
    const pass = auth[1]

    try {
      // Pass hwid as query param to license validation server
      const licenseCheckResponse = await fetch(
        LICENSE_SERVER_URL + pass + "&host=" + req.headers.host + "&hwid=" + encodeURIComponent(hwid)
      )
      const licenseCheck = (await licenseCheckResponse.json())["status"]

      console.log(
        LICENSE_SERVER_URL + pass + "&host=" + req.headers.host + "&hwid=" + hwid + " returned " + licenseCheck
      )

      if (licenseCheck === "License valid") {
        // Log or save HWID as needed here
        res.cookie("authcheck", "true", {
          expires: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
        })
        res.send("<script> window.location.href = window.location.href </script>")
        return
      }

      MasqFail(req, res)
    } catch (error) {
      console.error(error)
      MasqFail(req, res)
    }
  })
}
