package rbac

import (
	"strings"

	"github.com/hyperledger/fabric-chaincode-go/pkg/cid"
	"github.com/hyperledger/fabric-chaincode-go/shim"
)

// AuthServiceInterface is used by chaincode to configure and use the auth package
type AuthServiceInterface interface {
	ValidateContractPerms(roles Roles, contractRef ContractRef) error
	WithContractAuth([]string, Contract, ContractRef) ([]byte, error)
}

type authService struct {
	clientIdentity  cid.ClientIdentity
	rolesAttr       string
	rolePermissions RolePermissions
	stub            shim.ChaincodeStubInterface
}

// New returns an AuthServiceInterface
func New(stub shim.ChaincodeStubInterface, clientIdentity cid.ClientIdentity, rolePermissions RolePermissions, rolesAttr string) (AuthServiceInterface, error) {
	a := authService{
		clientIdentity:  clientIdentity,
		rolePermissions: rolePermissions,
		rolesAttr:       rolesAttr,
		stub:            stub,
	}
	return a, nil
}

// getRoles returns the roles of the current user
func (a authService) getRoles() (Roles, error) {
	// Get groups attr
	irf := a.rolesAttr
	val, found, err := a.clientIdentity.GetAttributeValue(irf)
	if err != nil {
		return nil, errAuthentication(err)
	}
	if !found {
		return nil, errRoles(irf)
	}
	return strings.Split(val, ","), nil
}

// ValidateContractPerms validates whether the given roles have permission to invoke a function
func (a authService) ValidateContractPerms(roles Roles, contractRef ContractRef) error {
	for _, role := range roles {
		// Lookup permissions
		perm, _ := a.rolePermissions[role].ContractPermissions[contractRef]
		if perm {
			return nil
		}
	}
	return errContract()
}

// WithContractAuth wraps a chaincode contract and only invokes the function if RBAC passes
func (a authService) WithContractAuth(args []string, contract Contract, contractRef ContractRef) ([]byte, error) {
	userRoles, err := a.getRoles()
	if err != nil {
		return nil, err
	}

	if err := a.ValidateContractPerms(userRoles, contractRef); err != nil {
		return nil, err
	}
	return contract(a.stub, args)
}
