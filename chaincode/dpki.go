package chaincode

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// SmartContract provides functions for managing an Asset
type DPKISmartContract struct {
	contractapi.Contract
}

// Asset describes basic details of what makes up a simple asset
type DPKIAsset struct {
	ID        string `json:"id"`
	Username  string `json:"username"`
	PublicKey string `json:"public_key"`
	Challenge string `json:"challenge"`
	IssuedOn  string `json:"issued_on"`
	RevokedOn string `json:"revoked_on"`
	Revoked   bool   `json:"revoked"`
}

// DPKIInitLedger adds a base set of dpki assets to the ledger.
func (s *DPKISmartContract) InitDPKILedger(ctx contractapi.TransactionContextInterface) error {

	// Create and populate values to dPKIAssets slice.
	dPKIAssets := []DPKIAsset{
		{ID: "GenesisDPKIAsset", Username: "NaN", PublicKey: "NaN", Challenge: "NaN", IssuedOn: time.Now().UTC().Format("2006-01-02")},
	}

	// Iterate through dPKIAssets slice and perform a PutState action for each dPKI asset.
	for _, dPKIAsset := range dPKIAssets {
		dPKIAssetJSON, err := json.Marshal(dPKIAsset)
		if err != nil {
			return err
		}

		err = ctx.GetStub().PutState(dPKIAsset.ID, dPKIAssetJSON)
		if err != nil {
			return fmt.Errorf("failed to put to world state. %v", err)
		}
	}

	return nil
}

// DPKIAssetExists returns true when asset with given ID exists in world state
func (s *DPKISmartContract) DPKIAssetExists(ctx contractapi.TransactionContextInterface, id string) (bool, error) {
	DPKIAssetJSON, err := ctx.GetStub().GetState(id)
	if err != nil {
		return false, fmt.Errorf("failed to read from world state: %v", err)
	}

	return DPKIAssetJSON != nil, nil
}

// CreateDPKIAsset issues the client's dPKI asset so that this is later used as a login token.
func (s *DPKISmartContract) CreateDPKIAsset(ctx contractapi.TransactionContextInterface, id string, username string, publicKey string) error {

	// Enable logging.
	log.SetOutput(io.MultiWriter(os.Stdout))

	// Check if the generated id is already used.
	exists, err := s.DPKIAssetExists(ctx, id)
	if err != nil {
		return err
	} else if exists {
		fmt.Errorf("dPKI Asset id given is already used. Please try again with a new id.")
	}

	// Parse and validate client's public key.
	block, _ := pem.Decode([]byte(publicKey))
	if block == nil {
		return fmt.Errorf("Invalid PEM format given.")
	}

	// Create the dPKI Asset model.
	dPKIAsset := DPKIAsset{
		ID:        id,
		Username:  username,
		PublicKey: publicKey,
		IssuedOn:  time.Now().UTC().Format("2006-01-02"),
	}

	// Marshal the afore mentioned asset to it's json form.
	dPKIAssetJSON, err := json.Marshal(dPKIAsset)
	fmt.Println("dPKIAssetJSON")
	fmt.Println(dPKIAssetJSON)
	if err != nil {
		return err
	}

	return ctx.GetStub().PutState(id, dPKIAssetJSON)
}

// ReadDPKIAsset returns the dPKI asset stored in the world state with given id.
func (s *DPKISmartContract) ReadDPKIAsset(ctx contractapi.TransactionContextInterface, id string) (*DPKIAsset, error) {

	// Enable logging.
	log.SetOutput(io.MultiWriter(os.Stdout))

	// Retrieve dPKI asset.
	dPKIAssetJSON, err := ctx.GetStub().GetState(id)
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if dPKIAssetJSON == nil {
		return nil, fmt.Errorf("the dPKI asset %s does not exist", id)
	}
	log.Println("Found dPKI asset:\n", dPKIAssetJSON)

	var dPKIAsset DPKIAsset
	// Marshal the afore mentioned asset to it's json form.
	err = json.Unmarshal(dPKIAssetJSON, &dPKIAsset)
	if err != nil {
		return nil, err
	}

	return &dPKIAsset, nil
}

// GetAllDPKIAssets returns all dpki assets found in world state.
func (s *DPKISmartContract) GetAllDPKIAssets(ctx contractapi.TransactionContextInterface) ([]*DPKIAsset, error) {
	// range query with empty string for startKey and endKey does an
	// open-ended query of all assets in the chaincode namespace.
	resultsIterator, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return nil, err
	}
	defer resultsIterator.Close()

	var dPKIAssets []*DPKIAsset
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}

		var dPKIAsset DPKIAsset
		err = json.Unmarshal(queryResponse.Value, &dPKIAsset)
		if err != nil {
			return nil, err
		}
		dPKIAssets = append(dPKIAssets, &dPKIAsset)
	}

	return dPKIAssets, nil
}

// UpdateDPKIAsset updates an existing asset in the world state with provided parameters.
func (s *DPKISmartContract) UpdateDPKIAsset(ctx contractapi.TransactionContextInterface, id string, challenge string, revoked bool) error {

	// Enable logging.
	log.SetOutput(io.MultiWriter(os.Stdout))
	var revokedOn string

	// Validate dPKI asset's existance.
	exists, err := s.DPKIAssetExists(ctx, id)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("the asset %s does not exist", id)
	}

	// Find client's dPKI asset.
	dPKIAsset, err := s.ReadDPKIAsset(ctx, id)

	if revoked {
		revokedOn = time.Now().UTC().Format("2006-01-02")
	}

	// Overwriting original asset with new asset.
	dPKIAssetNew := DPKIAsset{
		ID:        dPKIAsset.ID,
		Username:  dPKIAsset.Username,
		PublicKey: dPKIAsset.PublicKey,
		Challenge: challenge,
		IssuedOn:  dPKIAsset.IssuedOn,
		RevokedOn: revokedOn,
		Revoked:   revoked,
	}
	dPKIAssetNewJSON, err := json.Marshal(dPKIAssetNew)
	if err != nil {
		return err
	}

	return ctx.GetStub().PutState(id, dPKIAssetNewJSON)
}

// AuthorizeDPKIAsset set's the challenge attribute of the client's dPKI asset.
// This is later signed with the client's private key and id fed to the login function so that the client gets to be authenticated.
func (s *DPKISmartContract) AuthorizeDPKIAsset(ctx contractapi.TransactionContextInterface, id string) error {

	// Enable logging.
	log.SetOutput(io.MultiWriter(os.Stdout))

	// Find client's dPKI asset.
	dPKIAsset, err := s.ReadDPKIAsset(ctx, id)
	if dPKIAsset.Revoked {
		return fmt.Errorf("Sorry, your dPKI asset's certificate has already been revoked on %v", dPKIAsset.RevokedOn)
	}

	// Parse and validate client's public key.
	block, _ := pem.Decode([]byte(dPKIAsset.PublicKey))
	if block == nil {
		return fmt.Errorf("Invalid PEM format given.")
	}

	// Parse the client's public RSA key given.
	_, err = x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("Invalid x509 public key format found while parsing dPKI asset: ", err)
	}

	// Set a hardcoded challenge so as to avoid peers response diversity. For testing purposes.
	challenge := "36kf94md93jnmgf84jd96j03u48t948yu4k5804yujb"

	// Update client's dPKI asset with the challenge attribute.
	err = s.UpdateDPKIAsset(ctx, id, challenge, false)
	if err != nil {
		return fmt.Errorf("An error occured while updating the client's dPKI asset: ", err)
	}

	return nil
}

// LoginDPKIAsset is the last step so as to validate that the client is registered to the system, by succesfully logging in.
func (s *DPKISmartContract) LoginDPKIAsset(ctx contractapi.TransactionContextInterface, id string, challenge string, signature string) error {

	// Enable logging.
	log.SetOutput(io.MultiWriter(os.Stdout))

	// Find client's dPKI asset.
	dPKIAsset, err := s.ReadDPKIAsset(ctx, id)
	if dPKIAsset.Revoked {
		return fmt.Errorf("Sorry, your dPKI asset's certificate has already been revoked on %v", dPKIAsset.RevokedOn)
	}

	// Check that the challenge given matches the one in client's dPKI asset.
	if challenge != dPKIAsset.Challenge {
		return fmt.Errorf("Challenge given does not match the one in client's dPKI asset.")
	}

	// Parse and validate client's public key.
	block, _ := pem.Decode([]byte(dPKIAsset.PublicKey))
	if block == nil {
		return fmt.Errorf("Invalid PEM format given.")
	}

	// Parse the client's public RSA key given.
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("Invalid x509 public key format found while parsing dPKI asset: ", err)
	}

	// Decode client's signature.
	signatureDecoded, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("An error occured while parsing client's signature: ", err)
	}

	// Verify client's signature.
	hash := sha256.Sum256([]byte(challenge))
	err = rsa.VerifyPKCS1v15(publicKey.(*rsa.PublicKey), crypto.SHA256, hash[:], signatureDecoded)
	if err != nil {
		return fmt.Errorf("An error occured while verifying client's signature: ", err)
	}

	log.Println("Congratulations! You have succesfully logged in to the system!")

	return nil
}
