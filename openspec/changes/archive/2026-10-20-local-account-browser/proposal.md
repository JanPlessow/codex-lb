# Local account browser

The account reauthentication action currently returns an ordinary sign-in link, so the dashboard's browser determines the login profile and network route. Provide an optional, local macOS capability that opens the selected account's persistent Chrome profile with the same direct or single-proxy route as its OAuth exchange. Add-account enrollment selects the route before authentication and atomically associates the resulting account with that persona.

This is a local customization. No upstream submission is planned. The scope includes proxy authentication without exposing credentials to the browser, persisted profile and listener ownership, route-change revocation, existing identity protections, and isolated verification followed by local deployment.
