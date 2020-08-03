package rbac_test

import (
	"github.com/hyperledger/fabric-chaincode-go/pkg/cid"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-chaincode-go/shimtest"
	"github.com/hyperledger/fabric-protos-go/peer"
	"github.com/stickypixel/hyperledger/rbac"
	"github.com/stretchr/testify/mock"
)

/*
 *
 * Setup all types for RBAC
 *
 */

type contractRef string

const (
	createTransfer contractRef = "createTransfer"
	createWallet   contractRef = "createWallet"
)

/*
 *
 * Setup all permission maps
 *
 */

var userContractPerms = rbac.ContractPermissions{
	createWallet: true,
}

var adminContractPerms = rbac.ContractPermissions{
	createTransfer: true,
	createWallet:   false,
}

var rolePerms = rbac.RolePermissions{
	"admin": {
		ContractPermissions: adminContractPerms,
	},
	"user": {
		ContractPermissions: userContractPerms,
	},
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

func (mc *mockCID) GetAttributeValue(attrName string) (value string, found bool, err error) {
	args := mc.Called(attrName)
	return args.String(0), args.Bool(1), args.Error(2)
}

func simpleSetup() (rbac.AuthServiceInterface, error) {
	stub := initEmptyStub()
	cid := new(mockCID)
	return rbac.New(stub, cid, rolePerms, "roles")
}
