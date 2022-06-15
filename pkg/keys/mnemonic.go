package keys

import (
	"fmt"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/RichCG888/gotron-sdk/pkg/keys/hd"
	"github.com/tyler-smith/go-bip39"
)

// FromMnemonicSeedAndPassphrase derive form mnemonic and passphrase at index
func FromMnemonicSeedAndPassphrase(mnemonic, passphrase string, index int) *secp256k1.PrivateKey {
	seed := bip39.NewSeed(mnemonic, passphrase)
	master, ch := hd.ComputeMastersFromSeed(seed, []byte("Bitcoin seed"))
	private, _ := hd.DerivePrivateKeyForPath(
		btcec.S256(),
		master,
		ch,
		fmt.Sprintf("44'/195'/0'/0/%d", index),
	)

	bytes := private[:]

	return secp256k1.PrivKeyFromBytes(bytes)
}
