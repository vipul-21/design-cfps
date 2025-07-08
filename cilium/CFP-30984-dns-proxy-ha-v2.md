# CFP-30984: toFQDN DNS proxy HA

**SIG: SIG-POLICY**

**Begin Design Discussion:** 2024-08-19

**Cilium Release:** 1.17

**Authors:** Hemanth Malla <hemanth.malla@datadoghq.com>, Vipul Singh <singhvipul@microsoft.com>, Tamilmani Manoharan <tamanoha@microsoft.com>

Status: Implementable

## Summary

Cilium agent uses a proxy to intercept all DNS queries and obtain necessary information to enforce FQDN network policies. However, the lifecycle of this proxy is coupled with the cilium agent. When an endpoint has a toFQDN network policy in place, cilium installs a redirect to capture all DNS traffic. So, when the agent is unavailable, all DNS requests time out, including when DNS name to IP address mappings are already in place for this name. DNS policy unload on shutdown can be enabled on the agent, but it works only when the L7 policy is set to * and the agent is shutdown gracefully.

This CFP introduces a standalone DNS proxy that can run alongside the Cilium agent, which should eliminate hard dependency for names that already have policy map entries in place.

## Motivation

Users rely on toFQDN policies to enforce network policies against traffic to destinations outside the cluster, typically to blob storage / other services on the internet. Rolling out the Cilium agent should not result in packet drops. Introducing a high availability (HA) mode will allow for increased adoption of toFQDN network policies in critical environments.

## Goals

* Introduce a streaming gRPC API for exchanging FQDN policy related information.
* Introduce a standalone DNS proxy (SDP) that binds on the same port as built-in proxy with SO_REUSEPORT.
* Enforce L7 DNS policy via SDP.

## Non-Goals

* Updating new DNS <> IP mappings when the agent is down is not in scope for this CFP. Solving for this scenario would likely be more involved and may require creation of a dedicated set of bpf maps. This will likely come with a performance penalty of having to perform multiple lookups. We will explore solutions for this in a future CFP.

## Proposal

### Overview

There are two parts to enforcing toFQDN network policy. L3/L4 policy enforcement against IP addresses resolved from an FQDN and policy enforcement on DNS requests (L7 DNS policy). To enforce L3/L4 policy, per endpoint policy bpf maps need to be updated. We'd like to avoid multiple processes writing entries to policy maps, so the standalone DNS proxy (SDP) needs a mechanism to notify agent of newly resolved FQDN <> IP address mappings. This CFP proposes exposing a new gRPC streaming API from the cilium agent. Since the connection is bi-directional, the cilium agent can reuse the same connection to notify the SDP of L7 DNS policy changes.

Additionally, SDP needs to translate the IP address to cilium identity to enforce the policy. This CFP proposes leveraging a local cache within the SDP, which is kept up to date using policy and identity information received from the Cilium agent. The focus of this CFP is to define the contract between the SDP and Cilium agent, ensuring the exchange of only the essential data required to enable high availability mode.
When an endpoint's DNS traffic is selected by an L7 policy, DNS requests and responses will be forwarded to their destinations via SDP even if cilium-agent is not running. So, clients re-resolving DNS to establish new connections will not be blocked anymore if the IP addresses from the new resolution are unchanged. Note that the L3/L4 policy for the resolved names should have already been plumbed when the agent was running.

In addition to existing unix domain socket (UDS) opened by the agent to host HTTP APIs, we'll need a new UDS for the gRPC streaming service with similar permissions.

### RPC Methods

Method : UpdateMappingRequest (Invoked from SDP to agent)

_rpc UpdateMappingRequest(FQDNMapping) returns (UpdateMappingResponse) {}_

Request :

```protobuf
// FQDN-IP mapping goalstate sent from SDP to agent 
message FQDNMapping {
    string fqdn = 1; // dns name
    repeated bytes record_ip = 2; // List of IPs corresponding to dns name
    uint32 ttl = 3;  // TTL of DNS record
    uint32 source_identity = 4; // Identity of the client making the DNS request
    bytes source_ip = 5; // IP address of the client making the DNS request
    uint32 response_code = 6; // DNS Response code as specified in RFC2316
}
```

Response :

```protobuf
// Ack returned by cilium agent to SDP on receiving FQDN-IP mapping update
message UpdateMappingResponse {
    ResponseCode response = 1;
}

// Response code returned by RPC methods.
enum ResponseCode {
    RESPONSE_CODE_UNSPECIFIED = 0;
    RESPONSE_CODE_NO_ERROR = 1;
    RESPONSE_CODE_FORMAT_ERROR = 2;
    RESPONSE_CODE_SERVER_FAILURE = 3;
    RESPONSE_CODE_NOT_IMPLEMENTED = 4;
    RESPONSE_CODE_REFUSED = 5;
}
```

Method : StreamPolicyState (Bi-directional streaming RPC)

_rpc StreamPolicyState(stream PolicyStateResponse) returns (stream PolicyState) {}_

From SDP:

```protobuf
// Ack sent from SDP to Agent on processing DNS policy rules
message PolicyStateResponse  {
    ResponseCode response = 1;
    string request_id = 2; // Request ID for which response is sent to
}
```

Response from Agent:

```protobuf
// DNServer identity, port and protocol the requests be allowed to
message DNSServer {
    uint32 dns_server_identity = 1;  // Identity of destination DNS server
    uint32 dns_server_port = 2;
    uint32 dns_server_proto = 3;
}

// L7 DNS policy specifying which requests are permitted to which DNS server
message DNSPolicy {
    uint32 source_endpoint_id = 1;  // Endpoint ID of the workload this L7 DNS policy should apply to
    repeated string dns_pattern = 2;  // Allowed DNS pattern this identity is allowed to resolve.
    repeated DNSServer dns_servers = 3; // List of DNS servers to be allowed to connect.
}

// L7 DNS policy snapshot of all local endpoints and identity to ip mapping of source 
// and destinatione egress endpoints enforcing fqdn rules.
message PolicyState {
    repeated DNSPolicy egress_l7_dns_policy = 1;
    string request_id = 2; // Random UUID based identifier which will be referenced in ACKs
    repeated IdentityToEndpointMapping identity_to_endpoint_mapping = 3; // Identity to Endpoint mapping for the DNS server and the source identity
}

// Cilium Identity ID to IP address mapping
message IdentityToEndpointMapping {
    uint32 identity = 1;
    repeated EndpointInfo endpoint_info = 2;
}

// cilium endpoint ipaddress and ID
message EndpointInfo {
    uint64 id = 1;
    repeated bytes ip = 2;
}```

_Note: `dns_pattern` follows the same convention used in CNPs. See <https://docs.cilium.io/en/stable/security/policy/language/#dns-based> for more details_

_Note: `PolicyState` contains the latest snapshot of DNS rules for all endpoints on the host. Sending a snapshot allows for dealing with deletions automatically_

### Load balancing

SDP and agent's DNS proxy will run on the same port using SO_REUSEPORT. By default, kernel will use round robin algorithm to distribute load evenly between all sockets in the reuseport group. If cilium agent's DNS proxy goes down, kernel will automatically switch all traffic to SDP and vice versa. In the future, we can consider using a custom bpf program to make SDP only act as a hot standby. See [PoC](https://github.com/hemanthmalla/reuseport_ebpf/blob/main/bpf/reuseport_select.c) / eBPF summit 2023 talk for more details.

### High Level Information Flow

* Agent starts up with gRPC streaming service (only after resources are synced from k8s)
* SDP starts up.
* Connects to gRPC service, retrying periodically until success.
* Agent sends current snapshot and identity to endpoint mappings for L7 DNS Policy enforcement via StreamPolicyState to SDP.
* On policy recomputation or updates to identity to endpoint mappings, agent invokes StreamPolicyState.
* On DNS request from the client, DNS request redirects to DNS proxy port.
* Kernel round robin load balances between SDP and built in proxy.
* Assuming SDP gets the request, SDP enforces L7 DNS policy.
  * Lookup identity based on IP address via local cache which is populated during StreamPolicyState call.
  * Check against policy snapshot if this identity is allowed to resolve the current DNS name and is allowed to talk to DNS server target identity (also needs lookup in identity to endpoint mapping).
* Make upstream DNS request from SDP.
* On response, SDP invokes UpdateMappingRequest() to notify agent of new mappings.
* Release DNS response after success from  UpdateMappingRequest() / timeout.

### Handling SDP <> Agent re-connections

* When the agent is unavailable, SDP will periodically attempt to re-connect to the streaming service. Any FQDN<>IP mappings resolved when the agent is down will be cached in SDP and `UpdateMappingRequest` will be retried after establishing the connection.
  * On a new connection from SDP, the agent will invoke `StreamPolicyState` to notify SDP of all L7 DNS policy rules as well as the identity to endpoint mapping for the DNS server and the source identity.

* SDP will not listen on the DNS proxy port until a connection is established with cilium agent and initial L7 DNS policy rules are received. Meanwhile, built-in DNS proxy will continue to serve requests. SDP relies on cilium agent for initial bootstrap. In future, we could make SDP retrieve initial policy information from other sources, but this is not in scope for this CFP.

### Handling Upgrades

Since SDP relies on the cilium agent for rules and identity to endpoint mappings, if cilium agent is upgraded first, agent should be able to send the latest policy snapshot to SDP. If SDP is upgraded first, it should be able to connect to the agent and receive the latest policy snapshot. The underlying assumption is that both components are compatible with each other's API changes, and any breaking changes are properly versioned and communicated.
During the upgrade, SDP will continue to use the existing policy snapshot until it receives a new snapshot from the agent. This ensures that there is no disruption in service during the upgrade process.
