// Package rbac provides role based access control to Hyperledger Fabric
package rbac

import (
	"encoding/json"

	"github.com/hyperledger/fabric-chaincode-go/pkg/cid"
	"github.com/hyperledger/fabric-chaincode-go/shim"
)

// AuthServiceInterface is exported so that it can be used by consuming applications as a helper.
type AuthServiceInterface interface {
	GetUserID() string
	ValidateContractPerms(contractName string) error
	ValidateQueryPerms(query string) (string, error)
	WithContractAuth(contractName string, args []string, contract ContractFunc) ([]byte, error)
}

// AuthService describes the auth service.
type AuthService struct {
	rolePermissions RolePermissions
	stub            shim.ChaincodeStubInterface
	userID          string
	userRoles       Roles
}

// New returns a concrete AuthService type.
func New(
	stub shim.ChaincodeStubInterface,
	clientIdentity cid.ClientIdentity,
	rolePermissions RolePermissions,
	rolesAttr string,
) (AuthService, error) {
	var a AuthService

	userID, err := clientIdentity.GetID()
	if err != nil {
		return a, errAuthentication(err)
	}

	userRoles, err := getRoles(clientIdentity, rolesAttr)
	if err != nil {
		return a, err
	}

	a = AuthService{
		rolePermissions: rolePermissions,
		stub:            stub,
		userID:          userID,
		userRoles:       userRoles,
	}

	return a, nil
}

// ValidateContractPerms validates whether the given roles have permission to invoke a contract.
func (a AuthService) ValidateContractPerms(contractName string) error {
	for _, role := range a.userRoles {
		// Lookup permissions
		perm := a.rolePermissions[role].ContractPermissions[contractName]
		if perm {
			return nil
		}
	}

	return errContract()
}

// GetUserID returns the current user ID.
func (a AuthService) GetUserID() string {
	return a.userID
}

// ValidateQueryPerms validates if user can perform query and enforces CouchDB query filters where required.
func (a AuthService) ValidateQueryPerms(q string) (string, error) {
	var newQ CDBQuery
	// Unmarshal in to a CDBQuery
	if err := json.Unmarshal([]byte(q), &newQ); err != nil {
		return "", errQueryMarshal(err)
	}

	// Pick out the doctype from the query
	resource := newQ.Selector["docType"]

	if resource == nil {
		return "", errQueryDocType()
	}

	for _, role := range a.userRoles {
		// Lookup permissions
		ruleFunc, ok := a.rolePermissions[role].QueryPermissions[resource.(string)]
		if !ok {
			continue
		}

		// Construct rules from the ruleFunc callback
		rules := ruleFunc(a.userID, a.userRoles)
		if !rules.Allow {
			continue
		}

		// Enforce any selector appends
		for k, v := range rules.SelectorAppend {
			newQ.Selector[k] = v
		}

		// Enforce any filter queries (no need to check for nil first)
		newQ.Fields = rules.FieldFilter

		// Marshal back to json bytes so it can be sent back as a string
		newQBytes, err := json.Marshal(newQ)
		if err != nil {
			return "", errMarshal(err)
		}

		return string(newQBytes), nil
	}

	return "", errQuery(resource.(string))
}

// WithContractAuth wraps a chaincode contract and only invokes it if contract RBAC passes.
func (a AuthService) WithContractAuth(contractName string, args []string, contract ContractFunc) ([]byte, error) {
	if err := a.ValidateContractPerms(contractName); err != nil {
		return nil, err
	}

	return contract(a.stub, args, a)
}
