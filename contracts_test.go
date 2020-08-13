package rbac_test

import (
	"github.com/hyperledger/fabric-chaincode-go/shim"

	"github.com/stickypixel/hyperledger/rbac"
)

var mockPayload = []byte("invoked")

func mockContract(stub shim.ChaincodeStubInterface, args []string, auth rbac.AuthServiceInterface) ([]byte, error) {
	return mockPayload, nil
}

func mockQueryContract(
	stub shim.ChaincodeStubInterface,
	args []string,
	auth rbac.AuthServiceInterface,
) ([]byte, error) {
	q, err := auth.ValidateQueryPerms(args[0])
	if err != nil {
		return nil, err
	}

	// In real scenarios, q can now be used to query the ledger and will only return results enforced by the rule.

	return []byte(q), nil
}
