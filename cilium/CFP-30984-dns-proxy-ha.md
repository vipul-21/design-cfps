# CFP-30984: toFQDN DNS proxy HA

**SIG: SIG-POLICY**

**Begin Design Discussion:** 2024-04-08

**Cilium Release:** 1.17

**Authors:** Hemanth Malla <hemanth.malla@datadoghq.com>, Vipul Singh <singhvipul@microsoft.com>

## Summary

Cilium agent uses a proxy to intercept all DNS queries and obtain necessary information for enforcing toFQDN network policies. However, the lifecycle of this proxy is coupled with cilium agent. When an endpoint has a toFQDN network policy in place, cilium installs a redirect to capture all DNS traffic. So, when the agent is unavailable all DNS requests time out, including when DNS name to IP address mappings are already in place for this name.DNS policy unload on shutdown can be enabled on agent, but it works only when L7 policy is set to * and agent is shutdown gracefully.

This CFP introduces a standalone DNS proxy that can be run alongside cilium agent which should eliminate the hard dependency on cilium agent atleast for names that are already resolved. 

## Motivation

Users rely on toFQDN policies to enforce network policies against traffic to remote destinations outside the cluster, typically to blob storage / other services on the internet. Rolling out cilium agent should not result in traffic being dropped. Introducing a high availablility (HA) mode will allow for adoption of toFQDN network policies in critical environments.

## Goals

* Introduce a streaming gRPC API for exchanging FQDN related policy information and endpoint related metadata.
* Introduce standalone DNS proxy (SDP) that binds on the same port as built-in proxy with SO_REUSEPORT and uses the above mentioned API to notify agent of new DNS resolutions.

## Non-Goals

* Updating new DNS <> IP mappings when agent is down is out of scope

## Proposal

### Overview

TODO : Add Image

There are two parts to enforcing toFQDN network policy. L4 policy enforcement against IP adresses resolved from a FQDN and policy enforcement on DNS requests (L7 DNS policy). In order to enforce L4 policy, per endpoint policy bpf maps need to be updated. We'd like to avoid multiple processes writing entries to policy maps, so the standalone DNS proxy (SDP) needs a mechansim to notify agent of newly resolved FQDN <> IP address mappings. This CFP proposes exposing a new gRPC streaming API from cilium agent to do this. Since the connection is bi-directional, cilium agent can re-use the same connection to notify the SDP of L7 DNS policy changes. Additionally SDP also needs to translate IP address to endpoint ID and identity in order to enforce policy by reusing the logic from agent's DNS proxy.

### RPC Methods

Method : UpdateMappings

_rpc UpdatesMappings(steam FQDNMapping) returns (Result){}_

Request : 
```
message FQDNMapping {
    string FQDN = 1;
    repeated bytes IPS = 2;
    int32 TTL = 3;
    bytes client_ip = 4;
    int32 response_code = 5;
}
```
Response : 
```
message Result {
    bool success = 1;
}
```

Method : UpdatesDNSRules

_rpc UpdatesDNSRules(Request) returns (stream DNSPolicyRules){}_

Request : 
```
message Result {
    message string = 1;
}
```
Response : 
```
message FQDNSelector {
  string match_name = 1;
  string match_pattern = 2;
}

message DNSPolicyRule {
  string selector_string = 1;
  repeated FQDNSelector port_rules= 2;
  repeated string match_labels = 3;
  repeated uint32 selections = 4;
}

message DNSPolicyRules {
  uint64 endpoint_id = 1;
  uint32 port = 2;
  repeated DNSPolicyRule rules = 3;
}
```

### Tracking policy updates to SDP instances

Since SDP can be deployed out of band and users can choose to completely disable built-in proxy to run multiple instances of SDP, agent should be prepared to handle multiple instances. In order to ensure all instances  have upto date policy revisions, agent will maintain a mapping of ACKed policy revision numbers against stream ID.


## Impacts / Key Questions

### Getting the DNS Rules

We need the DNS Rules for the Standalone DNS proxy to enforce the L7 DNS policy. The policy are the source of turth for the rules and are propagated to the agent when we apply the policy. We explore the options to get the DNS rules for the DNS proxy.

#### Option 1: Running the GRPC sever in the agent[Recommended]

We can run a gRPC server in the agent to serve the DNS rules to the DNS proxy. SDP will be responsible for creating the connection with the agent. And once SDP establish a connection agent can keep track of the stream and send the DNS rules to the SDP. Agent can then reuse the same stream to send updates in the DNS rules.
In case, cilium agent is still not up, SDP will keep trying to connect to the agent until the connection is established. 

##### Pros

* SDP instances has the responsibility to connect to the agent. Agent does not care if the SDP is up or not.
* Reusing the same stream will be effiecient in terms of resources as we are not creating/destroying the stream for every update.

##### Cons

* An overhead on the cilium agent to keep track of the streams of the connected SDP instances.
* Streams are not thread safe, so if we have multiple threads using the same stream we will need to handle the synchronization.
* If SDP in future decides to handle policy updates as well, it will be trick. SDP needs to keep trying to sync with CA as well as CA needs to keep a track of the SDP instances to send updates.

![standalone-dns-proxy-up-scenario](./images/standalone-dns-proxy-up-scenario.png)
![standalone-dns-proxy-down-scenario](./images/standalone-dns-proxy-down-scenario.png)


#### Option 2: Running the GRPC server in the SDP as well

SDP can also runs a grpc server so that the agent can send the DNS rules to the SDP when the rules are ready instead of keeping alive the stream. On startup/restart SDP follows the same pattern as that of single grpc server, it asks for DNS rules from Cilium agent. For policy updates, agent just sends the data to server running at SDP.

##### Pros

* No overhead on the agent to keep a track of the open streams with the SDP.
* Better fault isolation(one stream failing does not affect the other streams)

##### Cons

* Resource intensive as we are creating a new stream for every update.
* If multiple SDP instance are running, we need to handle multiple grpc server on same address:port and send updates to each server froma agent.

#### Option 3: Reading the ep_config.json file in the SDP

We can read the DNS rules from the `ep_config.json` file. SDP will listen on the changes to the file and update the DNS rules accordingly. Cilium agent is the only one that writes to the file. Currently DNS rules are stored in the ep_config.json lazily as we only need those when DNS proxy restarts. We need to make sure that the DNS rules are updated in the file as soon as the policy is applied.
Storing the dns rules will require identities associated with the selector labels as current dns proxy implementation uses that to filter the DNS traffic OR will need to change the way dns porxy filters the DNS requests.

##### Pros

* No need to run a gRPC server in the agent/SDP.
* Removes the dependency on the agent to get the DNS rules.

##### Cons

* Will change the current implmentation/flow of flitering the dns requests.
* Reading a file might not be as efficient as reading from a gRPC server.


### Discovering endpoint metadata from SDP

In order to enforce L7 DNS policy, SDP needs to translate IP address to endpoint ID and identity ID. The simplest option is to reuse the same gRPC stream and implement another method to get the mappings from cilium agent. Since the actual source of truth are the bpf maps. Should the SDP be allowed to directly read from bpf maps ?


### Option 1: gRPC method

#### Pros

* Avoid interacting with low-level details. Simpler to maintain and stay upto date with any datapath changes.
* All data can be cached in-memory, in an event of agent being unavailable, SDP can lookup from in-memory cache

#### Cons

* Reliance on gRPC call in the hot-path
* In an event where SDP restarts when agent's gRPC service is unavailable, all cached state is lost and SDP cannot translate IP to endpoint ID or identity.

### Option 2: Read from bpf maps

#### Pros

* Reduced resource utilization in agent since agent doesn't need to process rpc calls in hotpath
* IP to endpoint ID or identity translation does not rely on agent availability.

#### Cons

* Low level interactions from components external to cilium agent.

### Q: Restoring L7 DNS policy when agent is unavailable

In an event where SDP restarts when agent's gRPC service is unavailable. SDP can read from the filesystem and restore the policy. The state is stored in `ep_config.json` file. So the flow would be first trying to connect to agent and if it fails, read from the file. This will be needed if we choose to run the gRPC options to get the DNSRules.

## Future Milestones

* Plumb toFQDN policy for new names when agent is unavailable
