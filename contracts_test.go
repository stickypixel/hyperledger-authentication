package rbac_test

import (
	"encoding/json"

	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/pkg/errors"

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
	q := rbac.CDBQuery{}
	if err := json.Unmarshal([]byte(args[0]), &q); err != nil {
		return nil, err
	}

	res, ok := q.Selector["docType"]
	if !ok {
		return nil, errors.New("docType not found in selector")
	}

	q, err := auth.ValidateQueryPerms(res.(string), operationQuery, q)
	if err != nil {
		return nil, err
	}

	// In real scenarios, q can now be used to query the ledger and will only return results enforced by the rule.

	return json.Marshal(q)
}
