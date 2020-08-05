package rbac_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/stickypixel/hyperledger/rbac"
)

func newQ(dt string) rbac.CDBQuery {
	return rbac.CDBQuery{
		Selector: rbac.CDBSelector{
			"docType": dt,
		},
		Limit: 10,
	}
}

func TestValidateContractPerms(t *testing.T) {
	tests := []struct {
		cRef     string
		cidRoles string
		allow    bool
		msg      string
	}{
		{
			cRef:     contractCreateTransfer,
			cidRoles: "user",
			allow:    false,
			msg:      "Should not allow",
		},
		{
			cRef:     contractCreateWallet,
			cidRoles: "user",
			allow:    true,
			msg:      "Should allow",
		},
		{
			cRef:     contractCreateTransfer,
			cidRoles: "admin",
			allow:    true,
			msg:      "Should allow",
		},
		{
			cRef:     contractCreateWallet,
			cidRoles: "admin",
			allow:    false,
			msg:      "Should not allow",
		},
	}

	for _, tt := range tests {
		t.Logf("%v %v to invoke %v contract", tt.msg, tt.cidRoles, tt.cRef)

		appAuth := simpleSetup(t, tt.cidRoles)
		err := appAuth.ValidateContractPerms(tt.cRef)

		if !tt.allow {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
		}
	}
}

func TestWithContractAuthErrors(t *testing.T) {
	var expSTType errors.StackTrace

	args := []string{mock.Anything}

	tests := []struct {
		cRef     string
		c        rbac.Contract
		expSC    int32
		expC     int32
		msg      string
		cidRoles string
		cidFound bool
		cidErr   error
	}{
		{
			cRef:     contractCreateTransfer,
			c:        mockContract,
			expSC:    http.StatusUnauthorized,
			expC:     rbac.CodeErrAuthentication,
			msg:      "when an error is returned from the CID",
			cidRoles: mock.Anything,
			cidFound: false,
			cidErr:   errors.New("some err from cid"),
		},
		{
			cRef:     contractCreateTransfer,
			c:        mockContract,
			expSC:    http.StatusForbidden,
			expC:     rbac.CodeErrRoles,
			msg:      "when the roleAttr is not found in the identity",
			cidRoles: mock.Anything,
			cidFound: false,
			cidErr:   nil,
		},
		{
			cRef:     contractCreateTransfer,
			c:        mockContract,
			expSC:    http.StatusForbidden,
			expC:     rbac.CodeErrContract,
			msg:      "when the role is not found in the permissions map",
			cidRoles: "anUnknownRole",
			cidFound: true,
			cidErr:   nil,
		},
		{
			cRef:     contractCreateTransfer,
			c:        mockContract,
			expSC:    http.StatusForbidden,
			expC:     rbac.CodeErrContract,
			msg:      "when contract invocation is not allowed",
			cidRoles: "user",
			cidFound: true,
			cidErr:   nil,
		},
	}

	for _, tt := range tests {
		t.Logf("Should return an error with code %v and HTTP status code %v %v", tt.expC, tt.expSC, tt.msg)

		stub := initEmptyStub()
		cid := new(mockCID)
		cid.On("GetAttributeValue", mock.Anything).Return(tt.cidRoles, tt.cidFound, tt.cidErr)
		cid.On("GetID", mock.Anything).Return(mock.Anything)

		appAuth, err := rbac.New(stub, cid, getRolePerms(), "roles")
		// If the New constructor didn't fail
		if err == nil {
			_, err = appAuth.WithContractAuth(tt.cRef, args, tt.c)
		}

		assert.Implements(t, (*error)(nil), err)
		assert.Implements(t, (*rbac.AuthErrorInterface)(nil), err)
		assert.IsType(t, (string)(""), err.Error())

		if assert.Error(t, err) {
			if e, ok := err.(rbac.AuthErrorInterface); ok {
				assert.Equal(t, tt.expC, e.Code())
				assert.Equal(t, tt.expSC, e.StatusCode())
				assert.IsType(t, expSTType, e.StackTrace())
			}
		}
	}
}

func TestWithContractAuth(t *testing.T) {
	args := []string{mock.Anything}

	tests := []struct {
		cRef     string
		c        rbac.Contract
		cidRoles string
	}{
		{
			cRef:     contractCreateWallet,
			c:        mockContract,
			cidRoles: "user",
		},
		{
			cRef:     contractCreateTransfer,
			c:        mockContract,
			cidRoles: "admin",
		},
	}

	for _, tt := range tests {
		t.Logf(
			"Should successfully return payload to a user with role %v from contract with ref %v", tt.cidRoles, tt.cRef,
		)

		appAuth := simpleSetup(t, tt.cidRoles)
		payload, err := appAuth.WithContractAuth(tt.cRef, args, tt.c)
		assert.NoError(t, err)
		assert.Equal(t, mockPayload, payload)
	}
}

func TestValidateResourcePermsQuery(t *testing.T) {
	tests := []struct {
		res      string
		cidRoles string
		expQ     string
		msg      string
	}{
		{
			res:      resourceTransfer,
			cidRoles: "user",
			expQ:     expQueryInTransfer,
			msg:      "alter the query to limit results to only transfers that the user was involved in",
		},
		{
			res:      resourceWallet,
			cidRoles: "user",
			expQ:     expQueryOnlyCreatedBy(resourceWallet),
			msg:      "alter the query to limit results to only wallets created by the user",
		},
		{
			res:      resourceTransfer,
			cidRoles: "admin",
			expQ:     doctypeQuery(resourceTransfer),
			msg:      "not alter the query",
		},
	}
	for _, tt := range tests {
		t.Logf("Should allow %v to %v %vs, and %v", tt.cidRoles, operationQuery, tt.res, tt.msg)

		appAuth := simpleSetup(t, tt.cidRoles)
		q, err := appAuth.ValidateQueryPerms(tt.res, operationQuery, newQ(tt.res))
		assert.NoError(t, err)

		qJSON, _ := json.Marshal(q)
		assert.JSONEq(t, tt.expQ, string(qJSON))
	}
}

func TestValidateResourcePermsDelete(t *testing.T) {
	tests := []struct {
		res      string
		op       string
		cidRoles string
		msg      string
		allow    bool
	}{
		{
			res:      resourceWallet,
			op:       operationDelete,
			cidRoles: "user",
			allow:    false,
			msg:      "Should not allow",
		},
		{
			res:      resourceTransfer,
			op:       operationDelete,
			cidRoles: "admin",
			allow:    true,
			msg:      "Should allow",
		},
		{
			res:      resourceWallet,
			op:       operationDelete,
			cidRoles: "admin",
			allow:    false,
			msg:      "Should not allow",
		},
	}
	for _, tt := range tests {
		t.Logf("%v %v to %v %vs", tt.msg, tt.cidRoles, tt.op, tt.res)

		appAuth := simpleSetup(t, tt.cidRoles)
		_, err := appAuth.ValidateQueryPerms(tt.res, tt.op, newQ(tt.res))

		if !tt.allow {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
		}
	}
}

func TestContractQuery(t *testing.T) {
	tests := []struct {
		args     []string
		cRef     string
		c        rbac.Contract
		cidRoles string
		expPL    string
		msg      string
	}{
		{
			args:     []string{doctypeQuery(resourceTransfer)},
			cRef:     contractQueryLedger,
			c:        mockQueryContract,
			cidRoles: "user",
			expPL:    expQueryInTransfer,
			msg:      "Should allow and return query adjusted for in transfer",
		},
		{
			args:     []string{doctypeQuery(resourceWallet)},
			cRef:     contractQueryLedger,
			c:        mockQueryContract,
			cidRoles: "user",
			expPL:    expQueryOnlyCreatedBy(resourceWallet),
			msg:      "Should allow and return query adjusted for owner only",
		},
		{
			args:     []string{doctypeQuery(resourceTransfer)},
			cRef:     contractQueryLedger,
			c:        mockQueryContract,
			cidRoles: "admin",
			expPL:    doctypeQuery(resourceTransfer),
			msg:      "Should allow and return untouched query",
		},
		{
			args:     []string{doctypeQuery(resourceAsset)},
			cRef:     contractQueryLedger,
			c:        mockQueryContract,
			cidRoles: "admin",
			expPL:    expQueryLimitFields(resourceAsset),
			msg:      "Should allow and return a query adjusted for limited fields",
		},
	}

	for _, tt := range tests {
		t.Logf(
			"%v as payload to user with role %v from contract with ref %v", tt.msg, tt.cidRoles, tt.cRef,
		)

		appAuth := simpleSetup(t, tt.cidRoles)
		payload, err := appAuth.WithContractAuth(tt.cRef, tt.args, tt.c)
		assert.NoError(t, err)
		assert.JSONEq(t, tt.expPL, string(payload))
	}
}

func TestContractQueryErrors(t *testing.T) {
	tests := []struct {
		args     []string
		cRef     string
		c        rbac.Contract
		cidRoles string
		expSC    int32
		expC     int32
		msg      string
	}{
		{
			args:     []string{doctypeQuery(resourceWallet)},
			cRef:     contractQueryLedger,
			c:        mockQueryContract,
			cidRoles: "admin",
			expSC:    http.StatusForbidden,
			expC:     rbac.CodeErrResource,
		},
	}

	for _, tt := range tests {
		t.Logf("Should return an error with code %v and HTTP status code %v", tt.expC, tt.expSC)

		appAuth := simpleSetup(t, tt.cidRoles)

		_, err := appAuth.WithContractAuth(tt.cRef, tt.args, tt.c)
		if assert.Error(t, err) {
			if e, ok := err.(rbac.AuthErrorInterface); ok {
				assert.Equal(t, tt.expC, e.Code())
				assert.Equal(t, tt.expSC, e.StatusCode())
			}
		}
	}
}
