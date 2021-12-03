# Private key to dirk/vouch distributed wallet converter

## how to run

```
./distwallet-plaintext --help
Usage of ./distwallet-plaintext:
  -config string
        Path to the config file. (default "./config.json")

```

**NOTE: the master private key is provided as an environment variable (`MASTER_PRIVATE_KEY`) and should be a hex representation of the private key, e.g. "3eb84bbe03db1c6341c490142a647655f33983ed693d0f43c696ed0378fdc492".**

Example:

```bash
go build -o distwallet-plaintext main.go && MASTER_PRIVATE_KEY=3eb84bbe03db1c6341c490142a647655f33983ed693d0f43c696ed0378fdc492 ./distwallet-plaintext
```

Sample `config.json`:

```
{
  "threshold": 2,
  "output_dir": "distwallets",
  "wallet_name": "distrib",
  "participants": [
    {
      "id": 70358052,
      "uri": "solana-multisig-1:8881",
      "passphrase": "secret1"
    },
    {
      "id": 46192271,
      "uri": "solana-multisig-1:8882",
      "passphrase": "secret2"
    },
    {
      "id": 76680527,
      "uri": "solana-multisig-1:8883",
      "passphrase": "secret3"
    }
  ]
}
```


`output_dir` - where the wallets with accounts will be generated, default "distwallets"

`walletname` - the wallet name, common for all N wallets

`passphrase` - passphrase, common for all wallets

`participants`  - an ordered array of participants, with ids (8-digits random number), hosts, and passphrases eg
```
		{70358052, "solana-multisig-1:8881", "secret1"},
		{46192271, "solana-multisig-2:8882", "secret2"},
		{76680527, "solana-multisig-3:8883", "secret3"},
```

`threshold` - threshold for signing, default 2

## outputs

N wallets with +1 account each (creates wallets if they don't exist, opens and add an account if wallet exists) with passphrases provided on input
```
./outdir/70358052/{wallet}
./outdir/46192271/{wallet}
./outdir/76680527/{wallet}
```

Should be moved to solana-multisig-1/solana-multisig-2/solana-multisig-3 hosts respectively, like in participants list. 

Will create a distributed account with name of first 4 bytes of account's composite public key in hex, e.g.

```
ethdo wallet accounts --base-dir distwallets/46192271 --wallet distrib
8633b210
94bd3cfb
```

Will fail if the account is already created.