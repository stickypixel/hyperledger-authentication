package rbac_test

import "github.com/stickypixel/hyperledger/rbac"

func allow(userID string, userRoles rbac.Roles) rbac.QueryRule {
	return rbac.QueryRule{Allow: true}
}

func disallow(userID string, userRoles rbac.Roles) rbac.QueryRule {
	return rbac.QueryRule{Allow: false}
}

func owner(userID string, userRoles rbac.Roles) rbac.QueryRule {
	return rbac.QueryRule{
		Allow: true,
		SelectorAppend: rbac.CDBSelector{
			"createdBy": userID,
		},
	}
}

func filterFields(userID string, userRoles rbac.Roles) rbac.QueryRule {
	return rbac.QueryRule{
		Allow:       true,
		FieldFilter: []string{"createdBy", "created"},
	}
}

func inTransfer(userID string, userRoles rbac.Roles) rbac.QueryRule {
	return rbac.QueryRule{
		Allow: true,
		SelectorAppend: rbac.CDBSelector{
			"$or": []rbac.CDBSelector{
				{"createdBy": userID},
				{"asset.from": userID},
				{"asset.to": userID},
				{"payment.from": userID},
				{"payment.to": userID},
			},
		},
	}
}
