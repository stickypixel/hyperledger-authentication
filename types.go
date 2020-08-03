package rbac

import (
	"github.com/hyperledger/fabric-chaincode-go/shim"
)

// If necessary, a method could be added to the empty interfaces to create more defined interfaces,
// which must be implemented by the consuming application's types.

// Roles is a string array of user roles
type Roles []string

// ContractRef is a reference to a Contract e.g. it's name or enum
type ContractRef interface{}

// Contract describes the function signature of an available chaincode Contract
type Contract func(shim.ChaincodeStubInterface, []string) ([]byte, error)

// ContractsMap maps function references to actual contract functions. e.g. Query: t.query
type ContractsMap map[ContractRef]Contract

// ContractPermissions is the base permissions for function invocation
type ContractPermissions map[ContractRef]bool

// Permissions describes the types of permissions the RolePermissions can have
type Permissions struct {
	ContractPermissions
}

// RolePermissions maps user role strings to Permissions.
type RolePermissions map[string]Permissions

// CDBSelector is a specific type for defining CouchDB selectors.
type CDBSelector map[string]interface{}
