package rbac

import (
	"github.com/hyperledger/fabric-chaincode-go/shim"
)

// If necessary, a method could be added to the empty interfaces to create more defined interfaces,
// which must be implemented by the consuming application's types.

// QueryRule describes a rule object.
type QueryRule struct {
	Allow          bool
	FieldFilter    []string
	SelectorAppend CDBSelector
}

// QueryRuleFunc describes the signature of a rule callback function.
type QueryRuleFunc func(userID string, userRoles []string) QueryRule

// QueryPermissions maps Resources to QueryRuleFuncs.
type QueryPermissions map[string]QueryRuleFunc

// ContractFunc describes the signature of a chaincode ContractFunc.
type ContractFunc func(stub shim.ChaincodeStubInterface, args []string, auth AuthServiceInterface) ([]byte, error)

// ContractPermissions is the base permissions for contract invocation.
type ContractPermissions map[string]bool

// Permissions describes the types of permissions the RolePermissions can have.
type Permissions struct {
	ContractPermissions
	QueryPermissions
}

// RolePermissions maps a roles to Permissions.
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
