# API1: Broken Object Level Authorization

- Also known as IDOR

- Attackers can exploit API endpoints that are vulnerable to broken object-level authorization by manipulating the ID of an object (UUID\`s, GUID\`s etc/)

- failing to properly and securely verify that a user has ownership and permission to view a specific resource through object-level authorization mechanisms can lead to data exposure

# API2: Broken Authentication

- An API suffers from Broken Authentication if any of its authentication mechanisms can be bypassed or circumvented.

- Attackers can gain complete control of other users accounts in the system, read their personal data, and perform sensitive actions on their behalf.

# API3: Broken Object Property Level Authorization

- APIs tend to expose endpoints that return all objects properties.

- Superset of two subclasses: **Excessive Data Exposure** and **Mass Assignment**
    - An API endpoint is vulnerable to Excessive Data Exposure if it reveals sensitive data to authorized users that they are not supposed to access.
    - An API endpoint is vulnerable to Mass Assignment if it permits authorized users to manipulate sensitive object properties beyond their authorized scope

# API4: Unrestricted Resource Consumption

- It's common to find APIs that do not limit client interactions or resource consumption

- Craft API requests, such as those including parameters that control the number of resources to be returned and performing response status/time/length analysis

- Exploitation can lead to DoS

# API5: Broken Function Level Authorization

- Exploitation requires the attacker to send legitimate API calls to an API endpoint that they should not have access to as non-privileged users. 

- allow attackers to access unauthorized functionality

# API6: Unrestricted Access to Sensitive Business Flows

- Usually involves understanding the business model backed by the API

- Exploitation might hurt the business in different ways

# API7: Server Side Request Forgery

- requires the attacker to find an API endpoint that accesses a URI that’s provided by the client

- Two types of SSRF:
    - basic SSRF when the response is returned to the attacker
    - Blind SSRF in which the attacker has no feedback on whether or not the attack was successful

- might lead to internal services enumeration, information disclosure, bypassing firewalls etc.

# API8: Security Misconfiguration

- Includes unpatched flaws, common endpoints, services running with insecure default configurations, or unprotected files and directories

# API9: Improper Inventory Management

- Threat agents usually get unauthorized access through old API versions or endpoints

- Simple Google Dorking, DNS enumeration, or using specialized search engines  will be enough to discover targets.

# API10: Unsafe Consumption of APIs

- APIs frequently interact with other APIs to exchange data, forming a complex ecosystem of interconnected services.

- Developers tend to trust and not verify the endpoints that interact with external or third-party APIs

- Attackers need to identify services the target API integrates with

- requires attackers to identify and potentially compromise other APIs/services the target API integrated with

