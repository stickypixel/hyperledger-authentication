package rbac

import (
	"strings"

	"github.com/hyperledger/fabric-chaincode-go/pkg/cid"
)

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

// appendSelector appends selectors to the supplied query to enforce result limiting.
func appendSelector(s CDBSelector, appS CDBSelector) CDBSelector {
	return CDBSelector{
		"$and": []CDBSelector{
			s,
			appS,
		},
	}
}
