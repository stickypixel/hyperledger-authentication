package rbac_test

import "github.com/stickypixel/hyperledger/rbac"

func allow(userID string, userRoles rbac.Roles) rbac.Rule {
	return rbac.Rule{Allow: true}
}

func disallow(userID string, userRoles rbac.Roles) rbac.Rule {
	return rbac.Rule{Allow: false}
}

func owner(userID string, userRoles rbac.Roles) rbac.Rule {
	return rbac.Rule{
		Allow: true,
		SelectorAppend: rbac.CDBSelector{
			"createdBy": userID,
		},
	}
}

func filterFields(userID string, userRoles rbac.Roles) rbac.Rule {
	return rbac.Rule{
		Allow:       true,
		FieldFilter: []string{"createdBy", "created"},
	}
}

func inTransfer(userID string, userRoles rbac.Roles) rbac.Rule {
	return rbac.Rule{
		Allow: true,
		SelectorAppend: rbac.CDBSelector{
			"$or": []rbac.CDBSelector{
				{"createdBy": userID},
				{"asset": fromOrTo(userID)},
				{"money": fromOrTo(userID)},
			},
		},
	}
}

func fromOrTo(userID string) rbac.CDBSelector {
	return rbac.CDBSelector{
		"$or": []rbac.CDBSelector{
			{"from": userID},
			{"to": userID},
		},
	}
}
