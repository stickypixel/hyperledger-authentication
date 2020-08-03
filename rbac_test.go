package rbac_test

import (
	"testing"

	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/stickypixel/hyperledger/rbac"
)

var contractPayload = []byte("invoked")

func mockContract(stub shim.ChaincodeStubInterface, args []string) ([]byte, error) {
	return contractPayload, nil
}

func TestValidateContractPerms(t *testing.T) {
	tests := []struct {
		cRef  contractRef
		roles []string
		allow bool
		msg   string
	}{
		{
			cRef:  createTransfer,
			roles: []string{"user"},
			allow: false,
			msg:   "Should not allow invocation",
		},
		{
			cRef:  createWallet,
			roles: []string{"user"},
			allow: true,
			msg:   "Should allow invocation",
		},
		{
			cRef:  createTransfer,
			roles: []string{"admin"},
			allow: true,
			msg:   "Should allow invocation",
		},
		{
			cRef:  createWallet,
			roles: []string{"admin"},
			allow: false,
			msg:   "Should not allow invocation",
		},
	}
	appAuth, err := simpleSetup()
	assert.NoError(t, err)
	for _, tt := range tests {
		t.Logf("%v, with roles '%v' and contract '%v'", tt.msg, tt.roles, tt.cRef)
		err := appAuth.ValidateContractPerms(tt.roles, tt.cRef)
		if !tt.allow {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
		}
	}
}

func TestWithContractAuthErrors(t *testing.T) {
	var expSTType errors.StackTrace
	args := []string{"any"}

	tests := []struct {
		cRef      contractRef
		c         rbac.Contract
		expSC     int32
		expC      int32
		rolesAttr string
		msg       string
		cidRole   string
		cidFound  bool
		cidErr    error
	}{
		{
			cRef:      createTransfer,
			c:         mockContract,
			rolesAttr: "anything",
			expSC:     401,
			expC:      4011,
			msg:       "unauthenticated, when an error is returned from the CID",
			cidRole:   "",
			cidFound:  false,
			cidErr:    errors.New("some err from cid"),
		},
		{
			cRef:      createTransfer,
			c:         mockContract,
			rolesAttr: "roles",
			expSC:     403,
			expC:      4031,
			msg:       "unauthorised access, when an invalid role is used",
			cidRole:   "anInvalidRole",
			cidFound:  false,
			cidErr:    nil,
		},
		{
			cRef:      createTransfer,
			c:         mockContract,
			rolesAttr: "roles",
			expSC:     403,
			expC:      4032,
			msg:       "unauthorised access, when contract invocation is not allowed",
			cidRole:   "user",
			cidFound:  true,
			cidErr:    nil,
		},
	}

	for _, tt := range tests {
		t.Logf("Should return an error with code %v and status code %v, %v", tt.expC, tt.expSC, tt.msg)
		stub := initEmptyStub()
		cid := new(mockCID)
		cid.On("GetAttributeValue", mock.Anything).Return(tt.cidRole, tt.cidFound, tt.cidErr)

		appAuth, err := rbac.New(stub, cid, rolePerms, tt.rolesAttr)
		assert.NoError(t, err)

		_, err = appAuth.WithContractAuth(args, tt.c, tt.cRef)
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
	args := []string{"any"}

	tests := []struct {
		cRef      contractRef
		c         rbac.Contract
		rolesAttr string
		cidRole   string
		cidFound  bool
		cidErr    error
	}{
		{
			cRef:      createWallet,
			c:         mockContract,
			rolesAttr: "roles",
			cidRole:   "user",
			cidFound:  true,
			cidErr:    nil,
		},
		{
			cRef:      createTransfer,
			c:         mockContract,
			rolesAttr: "roles",
			cidRole:   "admin",
			cidFound:  true,
			cidErr:    nil,
		},
	}

	for _, tt := range tests {
		t.Logf("Should successfully return the payload to a user with the role %v, from the contract with ref %v", tt.cidRole, tt.cRef)
		stub := initEmptyStub()
		cid := new(mockCID)
		cid.On("GetAttributeValue", mock.Anything).Return(tt.cidRole, tt.cidFound, tt.cidErr)

		appAuth, err := rbac.New(stub, cid, rolePerms, tt.rolesAttr)
		assert.NoError(t, err)

		payload, err := appAuth.WithContractAuth(args, tt.c, tt.cRef)
		assert.NoError(t, err)
		assert.Equal(t, contractPayload, payload)
	}
}
