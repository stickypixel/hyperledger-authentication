// Package rbac provides role based access control to Hyperledger Fabric
package rbac

import (
	"github.com/hyperledger/fabric-chaincode-go/pkg/cid"
	"github.com/hyperledger/fabric-chaincode-go/shim"
)

// AuthServiceInterface is exported so that it can be used by consuming applications as a helper.
type AuthServiceInterface interface {
	ValidateContractPerms(function ContractRef) error
	ValidateQueryPerms(resource, operation string, query CDBQuery) (CDBQuery, error)
	WithContractAuth(function ContractRef, args []string, contract Contract) ([]byte, error)
}

// AuthService describes our service.
type AuthService struct {
	rolePermissions RolePermissions
	rolesAttr       string
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
) (a AuthService, err error) {
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
		rolesAttr:       rolesAttr,
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

// ValidateQueryPerms validates if given roles have permission to perform the given operation on the given resource.
// It also enforces CouchDB query filters where required.
func (a AuthService) ValidateQueryPerms(resource, operation string, q CDBQuery) (CDBQuery, error) {
	for _, role := range a.userRoles {
		// Lookup permissions
		ruleFunc, ok := a.rolePermissions[role].ResourcePermissions[resource][operation]
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
			q.Selector = appendSelector(q.Selector, rules.SelectorAppend)
		}

		// Enforce any filter queries (no need to check for nil first)
		q.Fields = rules.FieldFilter

		return q, nil
	}

	return q, errResource()
}

// WithContractAuth wraps a chaincode contract and only invokes it if contract RBAC passes.
func (a AuthService) WithContractAuth(function ContractRef, args []string, contract Contract) ([]byte, error) {
	if err := a.ValidateContractPerms(function); err != nil {
		return nil, err
	}

	return contract(a.stub, args, a)
}
