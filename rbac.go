package rbac

import (
	"github.com/hyperledger/fabric-chaincode-go/pkg/cid"
	"github.com/hyperledger/fabric-chaincode-go/shim"
)

// AuthServiceInterface is used by chaincode to configure and use the auth package
type AuthServiceInterface interface {
	ValidateContractPerms(function ContractRef) error
	WithContractAuth(function ContractRef, args []string, contract Contract) ([]byte, error)
}

type authService struct {
	rolePermissions RolePermissions
	rolesAttr       string
	stub            shim.ChaincodeStubInterface
	userID          string
	userRoles       Roles
}

// New returns an AuthServiceInterface
func New(stub shim.ChaincodeStubInterface, clientIdentity cid.ClientIdentity, rolePermissions RolePermissions, rolesAttr string) (AuthServiceInterface, error) {
	userID, err := clientIdentity.GetID()
	if err != nil {
		return nil, errAuthentication(err)
	}

	userRoles, err := getRoles(clientIdentity, rolesAttr)
	if err != nil {
		return nil, err
	}

	a := authService{
		rolePermissions: rolePermissions,
		rolesAttr:       rolesAttr,
		stub:            stub,
		userID:          userID,
		userRoles:       userRoles,
	}

	return a, nil
}

// ValidateContractPerms validates whether the given roles have permission to invoke a function
func (a authService) ValidateContractPerms(contractRef ContractRef) error {
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
func (a authService) WithContractAuth(function ContractRef, args []string, contract Contract) ([]byte, error) {
	if err := a.ValidateContractPerms(function); err != nil {
		return nil, err
	}

	return contract(a.stub, args, a.userID, a.userRoles)
}
