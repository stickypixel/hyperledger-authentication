package rbac

import (
	"github.com/hyperledger/fabric-chaincode-go/shim"
)

// If necessary, a method could be added to the empty interfaces to create more defined interfaces,
// which must be implemented by the consuming application's types.

// Roles is a string array of user roles.
type Roles []string

// OperationPermissions maps operations to individual rules.
type OperationPermissions map[string]RuleFunction

// ResourcePermissions maps Resources to OperationPermissions.
type ResourcePermissions map[string]OperationPermissions

// ContractRef is a reference to a Contract e.g. it's name or enum.
type ContractRef interface{}

// Contract describes the signature of a chaincode Contract.
type Contract func(stub shim.ChaincodeStubInterface, args []string, auth AuthServiceInterface) ([]byte, error)

// ContractsMap maps function references to actual contract functions. e.g. Query: t.query.
type ContractsMap map[ContractRef]Contract

// ContractPermissions is the base permissions for function invocation.
type ContractPermissions map[ContractRef]bool

// Permissions describes the types of permissions the RolePermissions can have.
type Permissions struct {
	ContractPermissions
	ResourcePermissions
}

// RolePermissions maps Roles to Permissions.
type RolePermissions map[string]Permissions

// CDBSelector describes a CouchDB selector.
type CDBSelector map[string]interface{}

// CDBQuery describes a CouchDB query.
type CDBQuery struct {
	Selector CDBSelector            `json:"selector,omitempty"`
	Limit    uint                   `json:"limit,omitempty"`
	Skip     uint                   `json:"skip,omitempty"`
	Fields   []string               `json:"fields,omitempty"`
	Sort     map[string]interface{} `json:"sort,omitempty"`
}

// Rule describes a rule object.
type Rule struct {
	Allow          bool
	FieldFilter    []string
	SelectorAppend CDBSelector
}

// RuleFunction describes the signature of a rule callback function.
type RuleFunction func(userID string, userRoles Roles) Rule
