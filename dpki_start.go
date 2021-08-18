/*
SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"log"

	"dpki/chaincode"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

func main() {
	dPKIAssetChaincode, err := contractapi.NewChaincode(&chaincode.DPKISmartContract{})
	if err != nil {
		log.Panicf("Error creating dPKI chaincode: %v", err)
	}

	if err := dPKIAssetChaincode.Start(); err != nil {
		log.Panicf("Error starting dPKI chaincode: %v", err)
	}
}
