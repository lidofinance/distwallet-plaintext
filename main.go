package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/herumi/bls-eth-go-binary/bls"
	e2wallet "github.com/wealdtech/go-eth2-wallet"
	distributed "github.com/wealdtech/go-eth2-wallet-distributed"
	unencrypted "github.com/wealdtech/go-eth2-wallet-encryptor-unencrypted"
	//keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"
	filesystem "github.com/wealdtech/go-eth2-wallet-store-filesystem"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// BLSID turns a uint64 in to a BLS identifier.
func BLSID(id uint64) *bls.ID {
	var res bls.ID
	buf := [8]byte{}
	binary.LittleEndian.PutUint64(buf[:], id)
	if err := res.SetLittleEndian(buf[:]); err != nil {
		panic(err)
	}
	return &res
}

func sample1() {
	fmt.Printf("sample1\n")
	var sec bls.SecretKey
	sec.SetByCSPRNG()
	msg := []byte("abc")
	pub := sec.GetPublicKey()
	sig := sec.SignByte(msg)
	fmt.Printf("verify=%v\n", sig.VerifyByte(pub, msg))
}

func main() {
	bls.Init(bls.BLS12_381)
	bls.SetETHmode(bls.EthModeDraft07)

	//todo: take input w/ commandline or json file, whatever is easier
	//todo: take as an input an ethdo wallet/account + passphrase
	//todo: take as an input participants json
	//todo: take as an input signing threshold
	//todo: output distributed wallets
	//todo: usage readme
	//optional:
	//todo: sanity checks on inputs
	//todo: clean up generally

	type participant struct {
		id  uint64
		uri string
	}
	//indir = ""
	outdir := "distwallets"
	walletname := "hdwallet"
	//account = "1"

	masterPrivateKeyStr := "11c3a427db67bbc885f5f9cd2e1057197ff4a0860787b0fe6045fa19d52cd777"

	participants := []participant{
		{70358052, "server1:443"},
		{46192271, "server2:443"},
		{76680527, "server3:443"},
	}

	signingThreshold := 2

	//todo: count number of participants
	participantsCount := 3

	var masterSK bls.SecretKey
	masterSKByte, _ := hex.DecodeString(masterPrivateKeyStr)
	masterSK.Deserialize(masterSKByte)

	//only 1st position in this two arrays matters
	masterSKs := []bls.SecretKey{}
	masterPKs := []bls.PublicKey{}
	masterSKs = append(masterSKs, masterSK)

	paritcipantsIDs := []bls.ID{}
	participantsSKs := []bls.SecretKey{}
	participantsPKs := []bls.PublicKey{}
	signatures := []bls.Sign{}

	for i := 1; i < signingThreshold; i++ {
		var sk bls.SecretKey
		sk.SetByCSPRNG() //this actually doesn't matter
		masterSKs = append(masterSKs, sk)
	}

	masterPKs = bls.GetMasterPublicKey(masterSKs)

	fmt.Printf("master priv %s\n", masterSK.SerializeToHexStr())
	fmt.Printf("master pub %s\n", masterSK.GetPublicKey().SerializeToHexStr())

	//todo do domain
	msg := []byte("abc")

	msg_sig := masterSK.SignByte(msg)

	fmt.Printf("verify=%v\n", msg_sig.VerifyByte(masterSK.GetPublicKey(), msg))

	for i := 0; i < participantsCount; i++ {
		id := BLSID(participants[i].id)

		paritcipantsIDs = append(paritcipantsIDs, *id)
		var sk bls.SecretKey
		sk.Set(masterSKs, id)
		participantsSKs = append(participantsSKs, sk)

		var pk bls.PublicKey
		pk.Set(masterPKs, id)
		participantsPKs = append(participantsPKs, pk)

		sig := sk.SignByte(msg)
		signatures = append(signatures, *sig)
	}

	idxss := [][]uint32{{1, 2}, {0, 2}, {0, 1}}

	for _, idxs := range idxss {
		subIDs := []bls.ID{}
		subSKs := []bls.SecretKey{}
		subPKs := []bls.PublicKey{}
		subSigs := []bls.Sign{}

		for i := 0; i < signingThreshold; i++ {
			idx := idxs[i]
			subIDs = append(subIDs, paritcipantsIDs[idx])
			subSKs = append(subSKs, participantsSKs[idx])
			subPKs = append(subPKs, participantsPKs[idx])
			subSigs = append(subSigs, signatures[idx])
		}

		var sec bls.SecretKey
		var pub bls.PublicKey
		var sig bls.Sign

		sec.Recover(subSKs, subIDs)
		fmt.Printf("recover priv %s\n", sec.SerializeToHexStr())
		pub.Recover(subPKs, subIDs)
		fmt.Printf("recover pub %s\n", pub.SerializeToHexStr())
		sig.Recover(subSigs, subIDs)
		fmt.Printf("verify=%v\n", sig.VerifyByte(masterSK.GetPublicKey(), msg))
	}

	// below is pseudocode, does not compile

	ctx := context.Background()
	//todo remove when debugging ends
	encryptor := unencrypted.New()

	verificationVector := fromPKArrray(masterPKArray) // cast to [][]byte{

	for i := 0; i < participantsCount; i++ {
		currentStore := outdir + "/" + i
		currentWalletName := walletname + "_dist_" + i
		//todo create dir if needed
		store := filesystem.New(filesystem.WithLocation(current_store))
		e2wallet.UseStore(store)
		e2wallet.UseEncryptor(encryptor)

		//todo open if exist, create if not
		if _, err := distributed.CreateWallet(ctx, currentWalletName, store, encryptor); err != nil {
			panic(err)
		}

		// Open a wallet
		currentWallet, err := e2wallet.OpenWallet(currentWalletName)
		if err != nil {
			panic(err)
		}

		err = wallet.(e2wtypes.WalletLocker).Unlock(context.Background(), nil)
		if err != nil {
			panic(err)
		}
		// Always immediately defer locking the wallet to ensure it does not remain unlocked outside of the function.
		defer wallet.(e2wtypes.WalletLocker).Lock(context.Background())

		verificationVector := fromPKArrray(masterPKArray) // [][]byte{

		subIDs = append(subIDs, paritcipantsIDs[idx])
		subSKs = append(subSKs, participantsSKs[idx])
		subPKs = append(subPKs, participantsPKs[idx])

		_, err = wallet.(e2wtypes.WalletDistributedAccountImporter).ImportDistributedAccount(context.Background(),
			//todo: first 4 bytes of public key in hex,
			participantsSKs[i],
			signingThreshold,
			verificationVector,
			participants,
			[]byte("my account secret")) //don't remember what that is; investigate
		if err != nil {
			panic(err)
		}

		wallet.(e2wtypes.WalletLocker).Lock(context.Background())

	}

}
