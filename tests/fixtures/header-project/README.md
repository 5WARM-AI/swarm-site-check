# Synthetic header project

This fixture represents example.com without contacting it. `public/_headers` starts without Referrer-Policy. Tests copy this project to a temporary directory, prepare a diff, require explicit approval, apply the header change and derive a synthetic response from that same file. The isolated re-check then observes the header. No website, account or deployment is used.
