package rbac

import (
	"github.com/hyperledger/fabric-chaincode-go/pkg/cid"
	"github.com/hyperledger/fabric-chaincode-go/shim"
)

// AuthServiceInterface is exported so that it can be used by consuming applications as a helper
type AuthServiceInterface interface {
	ValidateContractPerms(function ContractRef) error
	WithContractAuth(function ContractRef, args []string, contract Contract) ([]byte, error)
}

// AuthService describes our service
type AuthService struct {
	rolePermissions RolePermissions
	rolesAttr       string
	stub            shim.ChaincodeStubInterface
	userID          string
	userRoles       Roles
}

// New returns a concrete AuthService type
func New(stub shim.ChaincodeStubInterface, clientIdentity cid.ClientIdentity, rolePermissions RolePermissions, rolesAttr string) (a AuthService, err error) {
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

// ValidateContractPerms validates whether the given roles have permission to invoke a function
func (a AuthService) ValidateContractPerms(contractRef ContractRef) error {
	for _, role := range a.userRoles {
		// Lookup permissions
		perm, _ := a.rolePermissions[role].ContractPermissions[contractRef]
		if perm {
			return nil
		}
	}

	return errContract()
}

// WithContractAuth wraps a chaincode contract and only invokes it if contract RBAC passes
func (a AuthService) WithContractAuth(function ContractRef, args []string, contract Contract) ([]byte, error) {
	if err := a.ValidateContractPerms(function); err != nil {
		return nil, err
	}

	return contract(a.stub, args, a.userID, a.userRoles)
}
