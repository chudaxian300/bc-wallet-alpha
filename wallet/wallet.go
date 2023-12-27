package wallet

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/fatih/color"
	"log"
	"math/big"
	"xlxblockchain/utils"
)

type Wallet struct {
	privateKey        *ecdsa.PrivateKey
	publicKey         *ecdsa.PublicKey
	blockchainAddress string
}

func NewWallet() *Wallet {

	w := new(Wallet)
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	w.privateKey = privateKey
	w.publicKey = &w.privateKey.PublicKey

	h := sha256.New()
	h.Write(w.publicKey.X.Bytes())
	h.Write(w.publicKey.Y.Bytes())
	digest := h.Sum(nil)
	address := base58.Encode(digest)
	w.blockchainAddress = address

	return w
}
func LoadWallet(privkey string) *Wallet {
	w := new(Wallet)
	pubKey := FromPriKeyToPubKey(privkey)
	privateKey := privkey
	privateKeyInt := new(big.Int)
	_, b := privateKeyInt.SetString(privateKey, 16)
	if !b {
		log.Println("privateKeyInt错误")
	}
	w.privateKey = &ecdsa.PrivateKey{
		PublicKey: pubKey,
		D:         privateKeyInt,
	}
	w.publicKey = &pubKey

	h := sha256.New()
	h.Write(w.publicKey.X.Bytes())
	h.Write(w.publicKey.Y.Bytes())
	digest := h.Sum(nil)
	address := base58.Encode(digest)
	w.blockchainAddress = address

	return w
}

//func LoadWallet(privkey string) *Wallet {
//	theWallet := new(Wallet)
//	thepriKey := new(ecdsa.PrivateKey)
//
//	privateKey := privkey
//	privateKey_D := new(big.Int)
//	privateKey_D.SetString(privateKey, 16)
//
//	thepriKey.D = privateKey_D
//
//	//得到 publicKey对象
//	// 曲线
//	curve := elliptic.P256()
//	// 获取公钥
//	x, y := curve.ScalarBaseMult(privateKey_D.Bytes())
//	publicKey := ecdsa.PublicKey{
//		Curve: curve,
//		X:     x,
//		Y:     y,
//	}
//
//	thepriKey.PublicKey = publicKey
//	theWallet.privateKey = thepriKey
//	theWallet.publicKey = &publicKey
//	log.Printf("%s", theWallet.privateKey)
//	log.Printf("%s", theWallet.publicKey)
//	//计算address
//	h := sha256.New()
//	h.Write(publicKey.X.Bytes())
//	h.Write(publicKey.Y.Bytes())
//
//	digest := h.Sum(nil)
//	// fmt.Printf("digest: %x\n", digest)
//	address := base58.Encode(digest)
//
//	theWallet.blockchainAddress = address
//
//	return theWallet
//}

func (w *Wallet) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		PrivateKey        string `json:"private_key"`
		PublicKey         string `json:"public_key"`
		BlockchainAddress string `json:"blockchain_address"`
	}{
		PrivateKey:        w.PrivateKeyStr(),
		PublicKey:         w.PublicKeyStr(),
		BlockchainAddress: w.BlockchainAddress(),
	})
}

func (w *Wallet) UnmarshalJSON(data []byte) error {
	var privateKey string
	v := &struct {
		PrivateKey *string `json:"private_key"`
	}{
		PrivateKey: &privateKey,
	}
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	loadWallet := LoadWallet(*v.PrivateKey)
	w.blockchainAddress = loadWallet.blockchainAddress
	w.publicKey = loadWallet.publicKey
	w.privateKey = loadWallet.privateKey
	return nil
}

// 为什么要写以下返回私钥和公钥的方法
func (w *Wallet) PrivateKey() *ecdsa.PrivateKey {

	return w.privateKey
}

func (w *Wallet) PrivateKeyStr() string {
	return fmt.Sprintf("%x", w.privateKey.D.Bytes())
}

func (w *Wallet) PublicKey() *ecdsa.PublicKey {
	return w.publicKey
}

func (w *Wallet) PublicKeyStr() string {
	return fmt.Sprintf("%x%x", w.publicKey.X.Bytes(), w.publicKey.Y.Bytes())
}

func (w *Wallet) BlockchainAddress() string {
	return w.blockchainAddress
}

// 序列化钱包
func (w *Wallet) Serialize() []byte {
	var result bytes.Buffer
	// 编码器
	marshalJSON, err := w.MarshalJSON()
	if err != nil {
		color.Red("解析JSON错误")
		log.Fatal(err)
	}
	encoder := gob.NewEncoder(&result)
	// 编码
	err = encoder.Encode(marshalJSON)
	if err != nil {
		color.Red("序列化区块错误")
		log.Fatal(err)
	}
	color.Blue("序列化钱包成功")
	return result.Bytes()
}

// 解析钱包
func DeserializeWallet(d []byte) *Wallet {
	var wallet Wallet
	var result []byte
	// 编码器
	decoder := gob.NewDecoder(bytes.NewReader(d))
	// 编码
	err := decoder.Decode(&result)
	if err != nil {
		color.Red("解析钱包错误")
		log.Fatal(err)
	}
	err = wallet.UnmarshalJSON(result)
	if err != nil {
		color.Red("解析JSON错误")
		log.Fatal(err)
	}
	color.Blue("解析钱包成功")
	return &wallet
}

func FromPriKeyToPubKey(privkey string) ecdsa.PublicKey {
	privateKey := privkey
	privateKeyInt := new(big.Int)
	privateKeyInt.SetString(privateKey, 16)
	//fmt.Println("privateKeyInt:", privateKeyInt)
	// 曲线
	curve := elliptic.P256()
	// 获取公钥
	x, y := curve.ScalarBaseMult(privateKeyInt.Bytes())
	publicKey := ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}
	//fmt.Println("Public Key : \n", publicKey)
	//fmt.Printf("Public Key X: %x\n", publicKey.X)
	//fmt.Printf("Public Key y: %x\n", publicKey.Y)
	return publicKey
}

//func FromPriKeyToPubKey(privkey string) *ecdsa.PublicKey  {
//	privateKey := privkey
//	privateKeyInt := new(big.Int)
//	privateKeyInt.SetString(privateKey, 16)
//	fmt.Println("privateKeyInt:", privateKeyInt)
//	// 曲线
//	curve := elliptic.P256()
//	// 获取公钥
//	x, y := curve.ScalarBaseMult(privateKeyInt.Bytes())
//	publicKey := ecdsa.PublicKey{
//		Curve: curve,
//		X:     x,
//		Y:     y,
//	}
//	fmt.Println("Public Key : \n", publicKey)
//	fmt.Printf("Public Key X: %x\n", publicKey.X)
//	fmt.Printf("Public Key y: %x\n", publicKey.Y)
//	return &publicKey
//}

type Transaction struct {
	senderPrivateKey           *ecdsa.PrivateKey
	senderPublicKey            *ecdsa.PublicKey
	senderBlockchainAddress    string
	recipientBlockchainAddress string
	value                      uint64
	hash                       string
}

func (t *Transaction) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Sender    string `json:"sender_blockchain_address"`
		Recipient string `json:"recipient_blockchain_address"`
		Value     uint64 `json:"value"`
		Hash      string `json:"hash"`
	}{
		Sender:    t.senderBlockchainAddress,
		Recipient: t.recipientBlockchainAddress,
		Value:     t.value,
		Hash:      t.hash,
	})
}

func NewTransaction(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey,
	sender string, recipient string, hash string, value uint64) *Transaction {
	return &Transaction{privateKey, publicKey, sender, recipient, value, hash}
}

func (t *Transaction) GenerateSignature() *utils.Signature {
	m, _ := json.Marshal(t)
	h := sha256.Sum256([]byte(m))
	r, s, _ := ecdsa.Sign(rand.Reader, t.senderPrivateKey, h[:])
	return &utils.Signature{R: r, S: s}
}

func (t *Transaction) Hash() [32]byte {
	m, _ := json.Marshal(t)
	return sha256.Sum256([]byte(m))
}
