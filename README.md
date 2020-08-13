# Introduction

## Why RBAC?

https://en.wikipedia.org/wiki/Role-based_access_control

### RBAC vs ACL

https://security.stackexchange.com/questions/346/what-is-the-difference-between-rbac-and-dac-acl/348

## Why not Hyperledger Fabric ACL in `configtx.yaml`?

Hyperledger Fabric already has a level of ACL (Access Control List): https://hyperledger-fabric.readthedocs.io/en/latest/access_control.html. However, it is limited to `peer`, `client` and `admin` as users and only `Readers`, `Writers`, `Admins` and `Endorsement` as operations. I believe it was designed to manage access very low level, not an application level and as such is more focused on chaincode operations such as creating channels, querying blocks and endorsing/commiting new chaincode. It does not have knowledge of all the resources and types of users / roles interacting with and existing on your ledger. So whilst it can be used to prevent certain users being able to write to the ledger, it can not prevent certain users from writing a certain piece of information or certain type of resource to the ledger.

## Why at the Chaincode Application Level?

As above, at a Fabric / Blockchain level, the ACL mechanisms in place do not have knowledge of your application, resources, users etc. Trying to implement it in the Fabric ACL, is the equivalent of trying to implement access controls to all your users at a Database level and is quite impractical or impossible. Blockchain or Database, they are both the 'respository' in our system. Generally, it is best to implement Auth at the lowest practical level - by that I mean as close to the source as possible. In a normal tech stack (e.g. UI, API, Database), we control access at the API level. The database is not (or at least should not) be publically available - it should only be possible to access it through the API. And for example, in the case of a micro-service API, there may also be multiple data stores and other sources that the public API talks to so implementing and maintaining the same access controls across all those resources would be very difficult. Therefore, it makes sense to implement the auth at that level - the API is the 'gateway' and implementing auth there means it can also act as gatekeeper.

If the API has a public endpoint, implementing Auth any higher up, in the UI for example, is completely ineffective, at least from a security point of view (though it can help from a UX standpoint). Even the most junior of hackers and bots will infiltrate it with ease.

So, where can we implement it in Hyperledger? We've concluded that it should be implemented at the gateway to the application, but where is that gateway? My first thought was, "I can do it in the SDK". My API / Gateway is using the SDK to create a very light REST API for communicating with my chaincode (I think like most people use it). I could treat the blockchain exactly like a database, make it unavailable to the public and control access through my API. Great! But... what happens when another organisation is added that I'm not part of? They wouldn't be forced to use the same API / Gateway as my application. So essentially, they would have free reign on my application's data. They would just need to login in to a peer and invoke one of our chaincode's contracts.

The only thing the organisations have in common in this scenario is the chaincode they are running. Therefore it makes sense to implement RBAC in the chaincode application and contracts. The application has knowledge of all the users, resources and operations that are possible within itself.

## Why not Private Data?

Private data is only implemented at an organisational level, not a user level. Hence, the Audit organisation may have access to all private data but he Audit Organisation will almost certainly also have different roles within its organisation that would also need fine grained access control.

# Adding Role Attributes to Hyperledger Identities

# RBAC Requirements

## Assumptions / Limitations

Assume that the chaincode only exposes multiple types of data by querying the CouchDB. For example, there should not be a chaincode function which can get or change mulitple resource types, directly by key. This is because this package will only restrict what is returned to the user by virtue of modifying CouchDB query strings and by restricting ability to invoking functions. It is expected that the chaincode would provide specific functions for creating, updating, deleting resources, e.g. createTransfer, deleteUser etc (this functionality will be added later)

# Roadmap

- Add operation-to-resource based permissions which will provide further fine-grained auth for CRUD style operations

## General

- Should allow the client application to define all roles, functions, doctypes and rules
- Should 'fail-safe' - i.e. should assume user does not have permission unless specified otherwise

## ContractFunc-Based Rules

- Should be able to control chaincode function invocation, based on the user's role and the requested function

## Resource-Based Rules

- Should be able to control the ability to query the CouchDB state database, based on the current user's role and the DocType
- Should provide the ability to filter CouchDB query results, based on the current user's role and DocType, by adjusting the selector
- Should provide the ability to filter fields in CouchDB query results, based on the current user's role and DocType, by adjusting the fields option in the query

# Example Rule Models

Permission and rule models are built by the consuming application, according to the following schemas:

## General Model

```
Role:
  - Contracts: (invocation)
    - ContractName
      - Allow/Disallow

  - Query:
    - Resource:
      - Rules:
        - Allow / Disallow
        - Fields Filter
        - Selector
```

## Example Model

```
Admin:
  - Contracts:
    - createAsset:
      - DisAllow

  - Query:
    - asset:
      - Rules:
        - Allow
        - No Filter
        - All Records

AssetHolder:
  - Contracts:
    - createAsset:
      - Allow

  - Query:
    - asset:
      - Rules:
        - Allow
        - Filter Internal Fields
        - Owner Records
```
