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
 * Setup all types for RBAC resources, operations and contractRefs
 *
 */

const (
	resourceAsset          = "asset"
	resourceTransfer       = "transfer"
	resourceWallet         = "wallet"
	operationGet           = "get"
	operationQuery         = "query"
	operationDelete        = "delete"
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
			ResourcePermissions: rbac.ResourcePermissions{
				resourceAsset: rbac.OperationPermissions{
					operationGet:    allow,
					operationQuery:  filterFields,
					operationDelete: disallow,
				},
				resourceTransfer: rbac.OperationPermissions{
					operationGet:    allow,
					operationQuery:  allow,
					operationDelete: allow,
				},
				resourceWallet: rbac.OperationPermissions{
					operationGet:   allow,
					operationQuery: disallow,
				},
			},
		},
		"user": {
			ContractPermissions: rbac.ContractPermissions{
				contractCreateWallet: true,
				contractQueryLedger:  true,
			},
			ResourcePermissions: rbac.ResourcePermissions{
				resourceTransfer: rbac.OperationPermissions{
					operationGet:    disallow,
					operationQuery:  inTransfer,
					operationDelete: disallow,
				},
				resourceWallet: rbac.OperationPermissions{
					operationGet:    disallow,
					operationQuery:  owner,
					operationDelete: disallow,
				},
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
