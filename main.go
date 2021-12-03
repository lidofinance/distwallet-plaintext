package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/herumi/bls-eth-go-binary/bls"
	e2wallet "github.com/wealdtech/go-eth2-wallet"
	distributed "github.com/wealdtech/go-eth2-wallet-distributed"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"
	filesystem "github.com/wealdtech/go-eth2-wallet-store-filesystem"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

const MasterPrivateKeyEnvName = "MASTER_PRIVATE_KEY"

var (
	configPath = flag.String("config", "./config.json", "Path to the config file.")
)

func init() {
	if err := bls.Init(bls.BLS12_381); err != nil {
		log.Fatalf("Failed to Init: %s", err)
	}

	if err := bls.SetETHmode(bls.EthModeDraft07); err != nil {
		log.Fatalf("Failed to SetETHmode: %s", err)
	}
}

func main() {
	flag.Parse()

	config, masterPrivateKeyStr, err := ReadConfig()
	if err != nil {
		log.Fatalf("Failed to ReadConfig: %s", err)
	}

	var masterSK bls.SecretKey
	masterSKByte, _ := hex.DecodeString(masterPrivateKeyStr)
	if err := masterSK.Deserialize(masterSKByte); err != nil {
		log.Fatalf("Failed to Deserialize master private key: %s", err)
	}

	// todo do domain
	msg := []byte("abc")
	masterSignedMsg := masterSK.SignByte(msg)
	if masterSignedMsg.VerifyByte(masterSK.GetPublicKey(), msg) {
		log.Println("successfully verified master SK signature")
	} else {
		log.Fatal("failed to verify master SK signature")
	}

	masterSKs, masterPKs := setupMasterKeys(config, masterSK)

	log.Printf("master pub %s\n", masterSK.GetPublicKey().SerializeToHexStr())

	participantsIDs, participantsSKs, participantsPKs, signatures := setupParticipants(config, masterSKs, masterPKs, msg)

	if err := checkKeys(config, masterSK, msg, participantsIDs, participantsSKs, participantsPKs, signatures); err != nil {
		log.Fatalf("failed to checkKeys: %s", err)
	}
	log.Println("keys check success")

	if err := saveWallets(config, masterPKs, participantsSKs); err != nil {
		log.Fatalf("failed to saveWallets: %s", err)
	}

	log.Printf("wallet saved to %s", config.OutputDir)
}

// newBlsID turns a uint64 in to a BLS identifier.
func newBlsID(id uint64) *bls.ID {
	var res bls.ID
	buf := [8]byte{}
	binary.LittleEndian.PutUint64(buf[:], id)
	if err := res.SetLittleEndian(buf[:]); err != nil {
		panic(err)
	}
	return &res
}

func bytesFromPKSlice(PKSlice []bls.PublicKey) [][]byte {
	var ret [][]byte
	for _, pk := range PKSlice {
		ret = append(ret, pk.Serialize())
	}
	return ret
}

type Participant struct {
	Id         uint64 `json:"id"`
	Uri        string `json:"uri"`
	Passphrase string `json:"passphrase"`
}

type Config struct {
	Threshold    int           `json:"threshold"`
	OutputDir    string        `json:"output_dir"`
	WalletName   string        `json:"wallet_name"`
	Participants []Participant `json:"participants"`
}

func ReadConfig() (config *Config, masterPrivateKey string, err error) {
	configBz, err := ioutil.ReadFile(*configPath)
	if err != nil {
		return nil, "", fmt.Errorf("failed to ReadFile (config: %s): %s", *configPath, err)
	}

	if err := json.Unmarshal(configBz, &config); err != nil {
		return nil, "", fmt.Errorf("failed to Unmarshal config: %s", err)
	}

	if len(config.Participants) < 2 {
		return nil, "", errors.New("participants count should be greater than 1")
	}

	if len(config.OutputDir) == 0 {
		return nil, "", errors.New("output directory not specified")
	}

	if len(config.WalletName) == 0 {
		return nil, "", errors.New("wallet name not specified")
	}

	if config.Threshold > len(config.Participants) || config.Threshold == 0 {
		return nil, "", fmt.Errorf("invalid threshold value %d (should be between 1 and %d)",
			config.Threshold, len(config.Participants))
	}

	// masterPrivateKeyStr := "3eb84bbe03db1c6341c490142a647655f33983ed693d0f43c696ed0378fdc492"

	masterPrivateKey, ok := os.LookupEnv(MasterPrivateKeyEnvName)
	if !ok {
		return nil, "", fmt.Errorf("MASTER_PRIVATE_KEY environment variable not specified")
	}
	if len(masterPrivateKey) != 64 {
		return nil, "", errors.New("invalid MASTER_PRIVATE_KEY")
	}

	return
}

func setupParticipants(config *Config, masterSKs []bls.SecretKey, masterPKs []bls.PublicKey, msg []byte) (
	participantsIDs []bls.ID,
	participantsSKs []bls.SecretKey,
	participantsPKs []bls.PublicKey,
	signatures []bls.Sign,
) {
	for i := 0; i < len(config.Participants); i++ {
		id := newBlsID(config.Participants[i].Id)

		participantsIDs = append(participantsIDs, *id)
		var sk bls.SecretKey
		if err := sk.Set(masterSKs, id); err != nil {
			log.Fatalf("Failed to Set secret key: %s", err)
		}
		participantsSKs = append(participantsSKs, sk)

		var pk bls.PublicKey
		if err := pk.Set(masterPKs, id); err != nil {
			log.Fatalf("Failed to Set public key: %s", err)
		}
		participantsPKs = append(participantsPKs, pk)

		sig := sk.SignByte(msg)
		signatures = append(signatures, *sig)
	}

	return
}

func setupMasterKeys(config *Config, masterSK bls.SecretKey) (masterSKs []bls.SecretKey, masterPKs []bls.PublicKey) {
	masterSKs = append(masterSKs, masterSK)

	for i := 1; i < config.Threshold; i++ {
		var sk bls.SecretKey
		sk.SetByCSPRNG() // This actually doesn't matter.
		masterSKs = append(masterSKs, sk)
	}

	masterPKs = bls.GetMasterPublicKey(masterSKs)

	return
}

func checkKeys(
	config *Config,
	masterSK bls.SecretKey,
	msg []byte,
	participantsIDs []bls.ID,
	participantsSKs []bls.SecretKey,
	participantsPKs []bls.PublicKey,
	signatures []bls.Sign,
) error {
	indexPairs := [][]uint32{{1, 2}, {0, 2}, {0, 1}}
	for idx, indexPair := range indexPairs {
		var (
			subIDs  []bls.ID
			subSKs  []bls.SecretKey
			subPKs  []bls.PublicKey
			subSigs []bls.Sign
		)

		for i := 0; i < config.Threshold; i++ {
			idx := indexPair[i]
			subIDs = append(subIDs, participantsIDs[idx])
			subSKs = append(subSKs, participantsSKs[idx])
			subPKs = append(subPKs, participantsPKs[idx])
			subSigs = append(subSigs, signatures[idx])
		}

		var sec bls.SecretKey
		var pub bls.PublicKey
		var sig bls.Sign

		if err := sec.Recover(subSKs, subIDs); err != nil {
			return fmt.Errorf("failed to Recover priv: %w", err)
		}

		if err := pub.Recover(subPKs, subIDs); err != nil {
			return fmt.Errorf("failed to Recover pub: %w", err)
		}

		if err := sig.Recover(subSigs, subIDs); err != nil {
			return fmt.Errorf("failed to Recover signature: %w", err)
		}

		if !sig.VerifyByte(masterSK.GetPublicKey(), msg) {
			return fmt.Errorf("failed to verify signature for index pair %d", idx)
		}
	}

	return nil
}

func saveWallets(config *Config, masterPKs []bls.PublicKey, participantsSKs []bls.SecretKey) error {
	ctx := context.Background()
	//todo remove when debugging ends
	encryptor := keystorev4.New()

	participantsMap := make(map[uint64]string)
	for _, participant := range config.Participants {
		participantsMap[participant.Id] = participant.Uri
	}

	accountName := masterPKs[0].SerializeToHexStr()[:8]
	verificationVector := bytesFromPKSlice(masterPKs) // cast to [][]byte{

	for idx := 0; idx < len(config.Participants); idx++ {
		err := func() error {
			currentStore := fmt.Sprintf("%s%s%d", config.OutputDir, "/", config.Participants[idx].Id)
			store := filesystem.New(filesystem.WithLocation(currentStore))
			if err := e2wallet.UseStore(store); err != nil {
				return fmt.Errorf("failed to UseStore: %w", err)
			}

			if _, err := store.RetrieveWallet(config.WalletName); err != nil {
				if _, err := distributed.CreateWallet(ctx, config.WalletName, store, encryptor); err != nil {
					return fmt.Errorf("failed to CreateWallet: %w", err)
				}
			}

			// Open a wallet
			currentWallet, err := e2wallet.OpenWallet(config.WalletName)
			if err != nil {
				return fmt.Errorf("failed to OpenWallet: %w", err)
			}

			err = currentWallet.(e2wtypes.WalletLocker).Unlock(context.Background(), nil)
			if err != nil {
				return fmt.Errorf("failed to Unlock wallet: %w", err)
			}
			// Immediately defer locking the wallet to ensure it does not remain unlocked outside the function.
			defer func(locker e2wtypes.WalletLocker, ctx context.Context) {
				err := locker.Lock(ctx)
				if err != nil {
					log.Printf("Failed to Lock the wallet for participant %s", config.Participants[idx].Uri)
				}
			}(currentWallet.(e2wtypes.WalletLocker), context.Background())

			currentPassphrase := []byte(config.Participants[idx].Passphrase)

			_, err = currentWallet.(e2wtypes.WalletDistributedAccountImporter).ImportDistributedAccount(context.Background(),
				accountName,
				participantsSKs[idx].Serialize(),
				uint32(config.Threshold),
				verificationVector,
				participantsMap,
				currentPassphrase) //don't remember what that is; investigate
			if err != nil {
				return fmt.Errorf("failed to ImportDistributedAccount: %w", err)
			}

			return nil
		}()
		if err != nil {
			return fmt.Errorf("failed to save wallet for participant %d: %w", idx, err)
		}
	}

	return nil
}
