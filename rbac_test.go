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

/*
 *
 * Tests for success
 *
 */

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

func TestWithContractAuth(t *testing.T) {
	args := []string{mock.Anything}

	tests := []struct {
		cRef     string
		c        rbac.ContractFunc
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

func TestValidateQueryPerms(t *testing.T) {
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
		t.Logf("Should allow %v to query %vs, and %v", tt.cidRoles, tt.res, tt.msg)

		appAuth := simpleSetup(t, tt.cidRoles)
		q := `{"selector": {"docType": "` + tt.res + `"}, "limit": 10}`
		payload, err := appAuth.ValidateQueryPerms(q)
		assert.NoError(t, err)

		qJSON, _ := json.Marshal(payload)
		assert.JSONEq(t, tt.expQ, string(qJSON))
	}
}

func TestContractQuery(t *testing.T) {
	tests := []struct {
		args     []string
		cRef     string
		c        rbac.ContractFunc
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

/*
 *
 * Tests for failures
 *
 */

func TestWithContractAuthErrors(t *testing.T) {
	var expSTType errors.StackTrace

	args := []string{mock.Anything}

	tests := []struct {
		cRef     string
		c        rbac.ContractFunc
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
			t.Logf("Should return an error with code %v and HTTP status code %v %v\nmsg: %v", tt.expC, tt.expSC, tt.msg, err)

			if e, ok := err.(rbac.AuthErrorInterface); ok {
				assert.Equal(t, tt.expC, e.Code())
				assert.Equal(t, tt.expSC, e.StatusCode())
				assert.IsType(t, expSTType, e.StackTrace())
			}
		}
	}
}

func TestContractQueryErrors(t *testing.T) {
	tests := []struct {
		args     []string
		cRef     string
		c        rbac.ContractFunc
		cidRoles string
		expSC    int32
		expC     int32
		msg      string
	}{
		{
			args:     []string{`{selector": {"docTypeeee": "anything"}, "limit": 10}`},
			cRef:     contractQueryLedger,
			c:        mockQueryContract,
			cidRoles: "admin",
			expSC:    http.StatusBadRequest,
			expC:     rbac.CodeErrQueryMarshal,
			msg:      "malformed json",
		},
		{
			args:     []string{`{"selector": {"notDocType": "anything"}, "limit": 10}`},
			cRef:     contractQueryLedger,
			c:        mockQueryContract,
			cidRoles: "admin",
			expSC:    http.StatusBadRequest,
			expC:     rbac.CodeErrQueryDocType,
			msg:      "missing doctype",
		},
		{
			args:     []string{doctypeQuery(resourceWallet)},
			cRef:     contractQueryLedger,
			c:        mockQueryContract,
			cidRoles: "admin",
			expSC:    http.StatusForbidden,
			expC:     rbac.CodeErrQuery,
			msg:      "user forbidden to query",
		},
	}

	for _, tt := range tests {
		appAuth := simpleSetup(t, tt.cidRoles)
		_, err := appAuth.WithContractAuth(tt.cRef, tt.args, tt.c)

		if assert.Error(t, err) {
			t.Logf("Should return an error with code %v and HTTP status code %v\nmsg: %v", tt.expC, tt.expSC, err)

			if e, ok := err.(rbac.AuthErrorInterface); ok {
				assert.Equal(t, tt.expC, e.Code())
				assert.Equal(t, tt.expSC, e.StatusCode())
			}
		}
	}
}

func TestValidateQueryPermsErrors(t *testing.T) {
	tests := []struct {
		res      string
		cidRoles string
		expSC    int32
		expC     int32
	}{
		{
			res:      resourceTransfer,
			cidRoles: "unknownRole",
			expSC:    http.StatusForbidden,
			expC:     rbac.CodeErrQuery,
		},
	}
	for _, tt := range tests {
		appAuth := simpleSetup(t, tt.cidRoles)
		q := `{"selector": {"docType": "` + tt.res + `"}, "limit": 10}`

		_, err := appAuth.ValidateQueryPerms(q)
		if assert.Error(t, err) {
			t.Logf("Should return an error with code %v and HTTP status code %v\nerr: %v", tt.expC, tt.expSC, err)

			if e, ok := err.(rbac.AuthErrorInterface); ok {
				assert.Equal(t, tt.expC, e.Code())
				assert.Equal(t, tt.expSC, e.StatusCode())
			}
		}
	}
}
