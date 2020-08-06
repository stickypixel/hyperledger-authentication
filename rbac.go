// Package rbac provides role based access control to Hyperledger Fabric
package rbac

import (
	"encoding/json"

	"github.com/hyperledger/fabric-chaincode-go/pkg/cid"
	"github.com/hyperledger/fabric-chaincode-go/shim"
)

// AuthServiceInterface is exported so that it can be used by consuming applications as a helper.
type AuthServiceInterface interface {
	ValidateContractPerms(function ContractRef) error
	ValidateQueryPerms(query string) (CDBQuery, error)
	WithContractAuth(function ContractRef, args []string, contract ContractFunc) ([]byte, error)
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

// ValidateContractPerms validates whether the given roles have permission to invoke a function.
func (a AuthService) ValidateContractPerms(contractRef ContractRef) error {
	for _, role := range a.userRoles {
		// Lookup permissions
		perm := a.rolePermissions[role].ContractPermissions[contractRef]
		if perm {
			return nil
		}
	}

	return errContract()
}

// ValidateQueryPerms validates if user can perform query and enforces CouchDB query filters where required.
func (a AuthService) ValidateQueryPerms(q string) (CDBQuery, error) {
	var newQ CDBQuery
	// Unmarshal in to a CDBQuery
	if err := json.Unmarshal([]byte(q), &newQ); err != nil {
		return newQ, errQueryMarshal(err)
	}

	// Pick out the doctype from the query
	resource := newQ.Selector["docType"]

	if resource == nil {
		return newQ, errQueryDocType()
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

		// Enforce any query appends
		if rules.SelectorAppend != nil {
			newQ.Selector = appendSelector(newQ.Selector, rules.SelectorAppend)
		}

		// Enforce any filter queries (no need to check for nil first)
		newQ.Fields = rules.FieldFilter

		return newQ, nil
	}

	return newQ, errQuery(resource.(string))
}

// WithContractAuth wraps a chaincode contract and only invokes it if contract RBAC passes.
func (a AuthService) WithContractAuth(function ContractRef, args []string, contract ContractFunc) ([]byte, error) {
	if err := a.ValidateContractPerms(function); err != nil {
		return nil, err
	}

	return contract(a.stub, args, a)
}
