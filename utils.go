package rbac

import (
	"strings"

	"github.com/hyperledger/fabric-chaincode-go/pkg/cid"
)

// getRoles returns the roles of the current logged in user
func getRoles(clientIdentity cid.ClientIdentity, rolesAttr string) (Roles, error) {
	val, found, err := clientIdentity.GetAttributeValue(rolesAttr)
	if err != nil {
		return nil, errAuthentication(err)
	}
	if !found {
		return nil, errRoles(rolesAttr)
	}
	return strings.Split(val, ","), nil
}
