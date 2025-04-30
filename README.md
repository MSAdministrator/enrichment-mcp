# Enrichment MCP Server

This project is a Model Context Protocol (MCP) server for performing enrichment given a provided observable. The combination of configured services and the provided observable(s) will determine which enrichment services to call.

This tool provides a simple MCP server implementation to perform third-party enrichment using common services (e.g. VirusTotal, Hybrid Analysis, etc.) utilizing the [security-cli](https://github.com/MSAdministrator/security-cli) python package to perform enrichment/communicate with different services.

## MCP Server

This implementation of the `enrichment-mcp` MCP server exposes the following [tools](https://modelcontextprotocol.io/docs/concepts/tools).

* lookup-observable - A generic endpoint which examines and routes the given observable to the correct tool.

## Supported Services

The following services and observable types are currently supported:

> If you have any suggestions or believe another service should be implemented, please create an issue or pull request!

| Name | API Key Required | Supports IP | Supports Domain | Supports URL | Supports Email |
|------|------------------|-------------|-----------------|--------------|----------------|
| VirusTotal | Yes        | Yes         | Yes             | Yes          | No             |
| HybridAnalysis | Yes    | Yes         | Yes             | Yes          | No             |
| AlienVault | Yes        | Yes         | Yes             | Yes          | No             |
| Shodan     | Yes        | Yes         | Yes             | Yes          | No             |
| Urlscan.io | Yes        | Yes         | Yes             | Yes          | No             |
| AbuseIPDB  | Yes        | Yes         | No              | No           | No             |
| HaveIBeenPwned | Yes    | No          | No              | No           | Yes            |

## Requirements

This MCP service uses `security-cli` and a custom [config.yaml.example](./config.yaml.example) file to determine which third-party enrichment services are supported for observable lookups.

The easiest way to run this on a local mac/system is:

```bash
uv run --env-file .env server.py
```

This requires that you use the provided template [.env.example](.env.example) and create a new `.env` file with your secrets.

> NOTE: Please review the documentation for [security-cli](https://github.com/MSAdministrator/security-cli) for information on configuring different services.
> The default will suffice for most use cases.

### Environmental Variables

> NOTE: It is highly recommended to set secrets as environmental variables when implementing this service. Stop storing secrets silly goose.

In order for the `security-cli` package to discover these variables, they must be in a specific format. Below is the list of currently supported variables:

* ENRICHMENT_MCP_VIRUSTOTAL_KEY
* ENRICHMENT_MCP_HYBRIDANALYSIS_KEY
* ENRICHMENT_MCP_ALIENVAULT_KEY
* ENRICHMENT_MCP_SHODAN_KEY
* ENRICHMENT_MCP_URLSCAN_KEY
* ENRICHMENT_MCP_ABUSEIPDB_KEY
* ENRICHMENT_MCP_HIBP_KEY

### Enrichments Configuration

Each enrichment service is defined in the `securiy-cli` config file. Additionally, I have broken out the different types of enrichment that can be performed. This means, in the current implementation, we have a single action type called `enrich` but in the future this can be expanded for things like `scans` or `queries` etc.

Underneath these high-level actions, we list out the observable type followed by a list of services that support that type. The currently supported observable types are:

* ipaddress - ipv4 addresses
* domain - A domain or netloc
* url - A fully qualified URL with schema, etc.
* email - A standard email address

We also support these types but they are currently not implemented:

* md5 - A file MD5 hash
* sha1 - A file SHA1 hash
* sha256 - A file SHA256 hash

Each service must have a `name` and a `template`. The `apikey` field can be provided but we recommend to use environmental variables.

### Prompt Templates

Each service and observable type can have it's own response template. These reside in the `security-cli` [templates](./templates/) directory and all templates are expected to exist here.

Each service defined has a prompt template using jinja2 templates. You can modify these are needed, but the format of the filename must remain the same. 

These files have the following filename pattern.

```bash
{service.name}.{enrichment.type}.jinja2
```

> Ensure that the response object has the correct fields in the template itself or you will receive an error.

Below is an example output for a prompt of `Enrich this IP 91.195.240.94` with some errors mixed in:

```python
{
    "virustotal": "error occurred looking up ip 91.195.240.94 in virustotal",
    "alienvault": "Service: alienvault\nIPAddress: \nReputation Score: 0\nTotal Votes: ",
    "shodan": "Service: shodan\nIPAddress: 91.195.240.94\nLast Analysis Results: 2025-04-25T21:02:52.644602\n\nTags\n\n\nAdditional information includes:\n\n* Latitude: 48.13743\n* Longitude: 11.57549\n* ASN: AS47846\n* Domains: ["servervps.net"]",
    "hybridanalysis": "error occurred looking up ip 91.195.240.94 in hybridanalysis",
    "urlscan": "Service: urlscan\nResult: https://urlscan.io/api/v1/result/01966efe-c8fa-74a4-bfc0-1ed479838e85/\n\nStats\n\n* uniqIPs - 6\n\n* uniqCountries - 2\n\n* dataLength - 432561\n\n* encodedDataLength - 218606\n\n* requests - 14\n\n\nPage\n* country - DE\n* server - Parking/1.0\n* ip - 91.195.240.94\n* mimeType - text/html\n* title - wearab.org\xa0-\xa0Informationen zum Thema wearab.\n* url - https://login.wearab.org/\n* tlsValidDays - 364\n* tlsAgeDays - 0\n* tlsValidFrom - 2025-04-25T00:00:00.000Z\n* domain - login.wearab.org\n* apexDomain - wearab.org\n* asnname - SEDO-AS SEDO GmbH, DE\n* asn - AS47846\n* tlsIssuer - Encryption Everywhere DV TLS CA - G2\n* status - 200\n",
    "abuseipdb": "Service: abuseripdb\nIPAddress: 91.195.240.94\nLast Analysis Result: 2025-03-30T14:04:45+00:00\nScore: 7\nUsage: Data Center/Web Hosting/Transit\nIs Tor: False\nIs Whitelisted: False\nISP: Sedo Domain Parking"
}
```

## MCP Server Usage

For using a pre-built server, instructions from here: https://modelcontextprotocol.io/quickstart/user

* Download Claude for Desktop
* Install uv
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```
* Download this repo and add to Claude for Desktop config
	* Claude for Desktop > Settings > Developer > Edit Config

> You can copy the provided [.desktop_config.example.json](.desktop_config.example.json) file 

If you want to create it yourself, these are the paths for Claude Desktop.

```bash
macOS: ~/Library/Application Support/Claude/claude_desktop_config.json
Windows: %APPDATA%\Claude\claude_desktop_config.json
```

Open up the configuration file in any text editor. Replace the file contents with this:

```json
{
	"mcpServers": {
		"enrichment-mcp": {
			"command": "/ABSOLUTE/PATH/TO/PARENT/FOLDER/uv",
			"args": [
				"--directory",
				"/ABSOLUTE/PATH/TO/CLONED/REPOSITORY/enrichment-mcp",
				"run",
				"server.py"
			]
		}
    }
}
```

4. Relaunch Claude for Desktop

You should now see two icons in the chat bar, a hammer which shows the tools available and a connection icon which shows the prompt defined and the input required.

## Contributing

Contributions are welcome! Please feel free to submit pull requests.
