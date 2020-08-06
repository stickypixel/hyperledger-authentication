package rbac_test

import (
	"testing"

	"github.com/hyperledger/fabric-chaincode-go/pkg/cid"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-chaincode-go/shimtest"
	"github.com/hyperledger/fabric-protos-go/peer"
	"github.com/stretchr/testify/mock"

	"github.com/stickypixel/hyperledger/rbac"
)

/*
 *
 * Setup all types for RBAC resources and contractRefs
 *
 */

const (
	resourceAsset          = "asset"
	resourceTransfer       = "transfer"
	resourceWallet         = "wallet"
	contractCreateTransfer = "createTransfer"
	contractCreateWallet   = "createWallet"
	contractQueryLedger    = "queryLedger"
)

/*
 *
 * Setup all permission maps
 *
 */

func getRolePerms() rbac.RolePermissions {
	return rbac.RolePermissions{
		"admin": {
			ContractPermissions: rbac.ContractPermissions{
				contractCreateTransfer: true,
				contractCreateWallet:   false,
				contractQueryLedger:    true,
			},
			QueryPermissions: rbac.QueryPermissions{
				resourceAsset:    filterFields,
				resourceTransfer: allow,
				resourceWallet:   disallow,
			},
		},
		"user": {
			ContractPermissions: rbac.ContractPermissions{
				contractCreateWallet: true,
				contractQueryLedger:  true,
			},
			QueryPermissions: rbac.QueryPermissions{
				resourceTransfer: inTransfer,
				resourceWallet:   owner,
			},
		},
	}
}

/*
 *
 * Create an empty chaincode interface
 *
 */

type emptyChaincode struct {
}

func (t *emptyChaincode) Init(stub shim.ChaincodeStubInterface) peer.Response {
	return shim.Success(nil)
}

func (t *emptyChaincode) Invoke(stub shim.ChaincodeStubInterface) peer.Response {
	return shim.Success(nil)
}

func initEmptyStub() (stub *shimtest.MockStub) {
	cc := new(emptyChaincode)
	stub = shimtest.NewMockStub("__TEST__", cc)
	stub.MockInit("__TEST_INIT__", nil)

	return stub
}

/*
 *
 * Create a mockCID so we can mock calls to the CID service
 *
 */

type mockCID struct {
	cid.ClientIdentity
	mock.Mock
}

func (mc *mockCID) GetID() (string, error) {
	args := mc.Called()
	return args.String(0), nil
}

func (mc *mockCID) GetAttributeValue(attrName string) (string, bool, error) {
	args := mc.Called(attrName)
	return args.String(0), args.Bool(1), args.Error(2)
}

func simpleSetup(t *testing.T, userRoles string) rbac.AuthServiceInterface {
	stub := initEmptyStub()
	cid := new(mockCID)
	cid.On("GetAttributeValue", "roles").Return(userRoles, true, nil)
	cid.On("GetID").Return("testuserID")

	appAuth, err := rbac.New(stub, cid, getRolePerms(), mock.Anything)

	if err != nil {
		t.Fatalf("New appAuth failed unexpectedly")
	}

	return appAuth
}
