# kanscan
Distributed NMAP vulnerability scanner and CVE matcher

## Description
This project is based on the idea behind flan scan from Cloudflare.  Rather than just being a single process responsible for scanning this is a message based system where scans can be ordered via an API with the results collected and formatted for eache request.  It also supports multiple can engines so scanning can scale much wider.
