# Scandalorian
Distributed NMAP vulnerability scanner and CVE matcher.  This repo only contains general information and the deployment files for ArgoCD.  It also contains the vscode workspace file used to develop the project.

## Description
This project is based on the idea behind flan scan from Cloudflare.  Rather than just being a single process responsible for scanning this is a message based system where scans can be ordered via an API with the results collected and formatted for each request.  It also supports multiple can engines so scanning can scale much wider.

## Development
Recently this project has undergone a bit of a rennovation. As services were added it was getting more unwieldy to have it in a monorepo and all of the components have since been broken out into separate repositories.  The repositories can be found here:

This is the main entry point and API surface for Scandalorian
[Scandalorian Ingest](https://github.com/charles-d-burton/scandalorian-ingest)

Package of type definitions and API
[Scandalorian Types](https://github.com/charles-d-burton/scandalorian-types)

Discovery Engine and Fast TCP Syn Scanner
[Scandalorian Discovery Engine](https://github.com/charles-d-burton/scandalorian-discovery-engine)

Scan Engine NMAP Wrapper for more in-depth scanning
[Scandalorian Scan Engine](https://github.com/charles-d-burton/scandalorian-scan-engine)

Reverse DNS Lookup Engine
[Scandalorian Reverse DNS](https://github.com/charles-d-burton/scandalorian-reversdns-engine)

DNS Zonewalk Engine for trying to find sub-domains
[Scandalorian Zonewalk Engine](https://github.com/charles-d-burton/scandalorian-zonewalk-engine)

Application Level Scanning Tool
[Scandalorian Application Engine](https://github.com/charles-d-burton/scandalorian-application-engine)

Result Collector for Saving Scan Results
[Scandalorian Collector](https://github.com/charles-d-burton/scandalorian-collector)


## TODOS

Update documentation
