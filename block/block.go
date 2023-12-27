package block

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/boltdb/bolt"
	"log"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
	"xlxblockchain/utils"
	"xlxblockchain/wallet"

	"github.com/fatih/color"
)

var MINING_DIFFICULT = 0x80000

const MINING_ACCOUNT_ADDRESS = "xielinxuan BLOCKCHAIN"
const MINING_REWARD = 5000
const MINING_TIMER_SEC = 10
const dbFile = "blockchain.db"
const blockBucket = "blocks"
const minerBucket = "miners"
const (
	//以下参数可以添加到启动参数
	BLOCKCHAIN_PORT_RANGE_START      = 5000
	BLOCKCHAIN_PORT_RANGE_END        = 5003
	NEIGHBOR_IP_RANGE_START          = 0
	NEIGHBOR_IP_RANGE_END            = 0
	BLOCKCHIN_NEIGHBOR_SYNC_TIME_SEC = 10
)

type Block struct {
	nonce        *big.Int
	number       *big.Int
	difficulty   *big.Int
	txSize       uint16
	hash         [32]byte
	previousHash [32]byte
	timestamp    uint64
	transactions []*Transaction
}

//func NewBlock(nonce int, previousHash [32]byte, number int, txs []*Transaction) *Block {
//	b := new(Block)
//	b.timestamp = time.Now().UnixNano()
//	b.nonce = nonce
//	b.previousHash = previousHash
//	b.transactions = txs
//	b.hash = b.Hash()
//	b.number = number
//	return b
//}

func NewBlock(nonce int, previousHash [32]byte, txs []*Transaction, number *big.Int) *Block {
	b := new(Block)
	b.timestamp = uint64(time.Now().UnixNano())
	b.nonce = big.NewInt(int64(nonce))
	b.previousHash = previousHash
	b.transactions = txs
	b.txSize = uint16(len(txs))
	b.hash = b.Hash()
	b.number = number
	b.difficulty = big.NewInt(int64(MINING_DIFFICULT))
	return b
}

func NewGenesisBlock(nonce int) *Block {
	b := new(Block)
	b.timestamp = uint64(time.Now().UnixNano())
	b.nonce = big.NewInt(int64(nonce))
	b.previousHash = [32]byte{}
	b.transactions = []*Transaction{}
	b.txSize = 0
	b.hash = b.Hash()
	b.number = big.NewInt(0)
	b.difficulty = big.NewInt(int64(MINING_DIFFICULT))
	return b
}

func (b *Block) PreviousHash() [32]byte {
	return b.previousHash
}

func (b *Block) Nonce() int64 {
	return b.nonce.Int64()
}

func (b *Block) Transactions() []*Transaction {
	return b.transactions
}

func (b *Block) Print() {
	log.Printf("%-15v:%30d\n", "timestamp", b.timestamp)
	//fmt.Printf("timestamp       %d\n", b.timestamp)
	log.Printf("%-15v:%30d\n", "nonce", b.nonce)
	log.Printf("%-15v:%30d\n", "number", b.number)
	log.Printf("%-15v:%30x\n", "previous_hash", b.previousHash)
	log.Printf("%-15v:%30x\n", "hash", b.hash)
	//log.Printf("%-15v:%30s\n", "transactions", b.transactions)
	for _, t := range b.transactions {
		t.Print()
	}
}

// 序列化区块
func (b *Block) Serialize() []byte {
	var result bytes.Buffer
	// 编码器
	marshalJSON, _ := b.MarshalJSON()
	encoder := gob.NewEncoder(&result)
	// 编码
	err := encoder.Encode(marshalJSON)
	if err != nil {
		color.Red("序列化区块错误")
		log.Fatal(err)
	}
	color.Blue("序列化区块成功")
	return result.Bytes()
}

// 解析区块
func DeserializeBlock(d []byte) *Block {
	var block Block
	var result []byte
	// 编码器
	decoder := gob.NewDecoder(bytes.NewReader(d))
	// 编码
	err := decoder.Decode(&result)
	if err != nil {
		color.Red("解析区块错误")
		log.Fatal(err)
	}
	err = block.UnmarshalJSON(result)
	if err != nil {
		color.Red("解析JSON错误")
		log.Fatal(err)
	}
	return &block
}

type Blockchain struct {
	transactionPool   []*Transaction
	chain             []*Block
	hash              []byte
	blockchainAddress string
	port              uint16
	mux               sync.Mutex
	db                *bolt.DB
	neighbors         []string
	muxNeighbors      sync.Mutex
}

type BlockchainIterator struct {
	currentHash []byte   // 当前区块hash
	db          *bolt.DB // 已经打开的数据库
}

// 新建一条链的第一个区块
// NewBlockchain(blockchainAddress string) *Blockchain
// 函数定义了一个创建区块链的方法，它接收一个字符串类型的参数 blockchainAddress，
// 它返回一个区块链类型的指针。在函数内部，它创建一个区块链对象并为其设置地址，
// 然后创建一个创世块并将其添加到区块链中，最后返回区块链对象。
func NewBlockchain(port uint16) *Blockchain {
	var blockChainHash []byte
	var minerWallet *wallet.Wallet
	bc := new(Blockchain)
	bc.port = port
	// 1.打开数据库文件
	db, _ := bolt.Open(dbFile, 0600, nil)
	// 2.更新数据库
	db.Update(func(tx *bolt.Tx) error {
		// 2.1 获取bucket
		buck := tx.Bucket([]byte(blockBucket))
		if buck == nil {
			// 2.2.1 第一次使用，创建创世块
			color.Green(strings.Repeat("=", 10) + "第一次使用，创建创世块" + strings.Repeat("=", 10))
			genesis := NewGenesisBlock(0) //创世纪块

			// 2.2.2 区块数据编码
			block_data := genesis.Serialize()

			// 2.2.3 创建新bucket, 存入创世区块信息
			blockBucket, _ := tx.CreateBucket([]byte(blockBucket))
			blockBucket.Put(genesis.hash[:], block_data)
			blockBucket.Put([]byte("last"), genesis.hash[:])
			blockChainHash = genesis.hash[:]
			color.Green(strings.Repeat("=", 10) + "初始化区块信息完成" + strings.Repeat("=", 10))

			minerBucket, _ := tx.CreateBucket([]byte(minerBucket))
			minerWallet = wallet.NewWallet()
			wallet_data := minerWallet.Serialize()
			minerBucket.Put([]byte(string(bc.port)), wallet_data)
			color.Green(strings.Repeat("=", 10) + "初始化矿工信息完成" + strings.Repeat("=", 10))
			genesis.Print()
		} else {
			// 2.3 不是第一次使用
			color.Green(strings.Repeat("=", 10) + "欢迎回来" + strings.Repeat("=", 10))
			db.View(func(tx *bolt.Tx) error {
				bucket := tx.Bucket([]byte(minerBucket))
				if wallet_data := bucket.Get([]byte(string(bc.port))); wallet_data == nil {
					minerWallet = wallet.NewWallet()
				} else {
					minerWallet = wallet.DeserializeWallet(wallet_data)
				}
				return nil
			})
			blockChainHash = buck.Get([]byte("last"))
		}
		bc.blockchainAddress = minerWallet.BlockchainAddress()
		bc.hash = blockChainHash
		bc.db = db
		color.Magenta("===矿工帐号信息====\n")
		color.Magenta("矿工private_key\n %v\n", minerWallet.PrivateKeyStr())
		color.Magenta("矿工publick_key\n %v\n", minerWallet.PublicKeyStr())
		color.Magenta("矿工blockchain_address\n %v\n", minerWallet.BlockchainAddress())
		color.Magenta("===============\n")
		return nil
	})

	return bc
}

func (bc *Blockchain) Iterator() *BlockchainIterator {
	return &BlockchainIterator{
		currentHash: bc.hash,
		db:          bc.db,
	}
}

func (i *BlockchainIterator) PreBlock() (*Block, bool) {
	var block *Block
	i.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(blockBucket))
		encodeBlock := b.Get(i.currentHash)
		block = DeserializeBlock(encodeBlock)
		return nil
	})
	i.currentHash = block.previousHash[:]
	return block, !Equal(block.previousHash, [32]byte{})
}

func Equal(slice1, slice2 [32]byte) bool {
	for i := range slice1 {
		if slice1[i] != slice2[i] {
			return false
		}
	}
	return true
}

func (bc *Blockchain) Chain() []*Block {
	return bc.chain
}

func (bc *Blockchain) Run() {

	bc.StartSyncNeighbors()
	bc.ResolveConflicts()
	bc.StartMining()
}

func (bc *Blockchain) SetNeighbors() {
	bc.neighbors = utils.FindNeighbors(
		utils.GetHost(), bc.port,
		NEIGHBOR_IP_RANGE_START, NEIGHBOR_IP_RANGE_END,
		BLOCKCHAIN_PORT_RANGE_START, BLOCKCHAIN_PORT_RANGE_END)

	color.Blue("邻居节点：%v", bc.neighbors)
}

func (bc *Blockchain) SyncNeighbors() {
	bc.muxNeighbors.Lock()
	defer bc.muxNeighbors.Unlock()
	bc.SetNeighbors()
}

func (bc *Blockchain) StartSyncNeighbors() {
	bc.SyncNeighbors()
	_ = time.AfterFunc(time.Second*BLOCKCHIN_NEIGHBOR_SYNC_TIME_SEC, bc.StartSyncNeighbors)
}

func (bc *Blockchain) TransactionPool() []*Transaction {
	return bc.transactionPool
}

func (bc *Blockchain) ClearTransactionPool() {
	bc.transactionPool = bc.transactionPool[:0]
}

func (bc *Blockchain) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Blocks          []*Block       `json:"chain"`
		TransactionPool []*Transaction `json:"transaction_pool"`
	}{
		Blocks:          bc.chain,
		TransactionPool: bc.transactionPool,
	})
}

func (bc *Blockchain) UnmarshalJSON(data []byte) error {
	v := &struct {
		Blocks *[]*Block `json:"chain"`
	}{
		Blocks: &bc.chain,
	}
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	return nil
}

// (bc *Blockchain) CreateBlock(nonce int, previousHash [32]byte) *Block
//  函数是在区块链上创建新的区块，它接收两个参数：一个int类型的nonce和一个字节数组类型的 previousHash，
//  返回一个区块类型的指针。在函数内部，它使用传入的参数来创建一个新的区块，
//  然后将该区块添加到区块链的链上，并清空交易池。

func (bc *Blockchain) CreateBlock(nonce int) *Block {
	var blockChainHash []byte
	var hash32 [32]byte
	var lastBlock []byte
	num := big.NewInt(0)
	bc.db.View(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(blockBucket))
		blockChainHash = buck.Get([]byte("last"))
		lastBlock = buck.Get(blockChainHash)
		copy(hash32[:], blockChainHash)
		return nil
	})

	last := DeserializeBlock(lastBlock)
	b := NewBlock(nonce, last.hash, bc.transactionPool, num.Add(last.number, big.NewInt(1)))
	bc.db.Update(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(blockBucket))
		bc.chain = append(bc.chain, b)
		bc.transactionPool = []*Transaction{}
		buck.Put(b.hash[:], b.Serialize())
		buck.Put([]byte("last"), b.hash[:])
		bc.hash = b.hash[:]
		return nil
	})
	b.Print()

	// 删除其他节点的交易
	for _, n := range bc.neighbors {
		endpoint := fmt.Sprintf("http://%s/transactions", n)
		client := &http.Client{}
		req, _ := http.NewRequest("DELETE", endpoint, nil)
		resp, _ := client.Do(req)
		log.Printf("%v", resp)
	}
	return b
}

func (bc *Blockchain) Print() {
	for i, block := range bc.chain {
		color.Green("%s BLOCK %d %s\n", strings.Repeat("=", 25), i, strings.Repeat("=", 25))
		block.Print()
	}
	color.Yellow("%s\n\n\n", strings.Repeat("*", 50))
}

func (b *Block) Hash() [32]byte {
	m, _ := json.Marshal(b)
	return sha256.Sum256([]byte(m))
}

func (b *Block) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Timestamp    uint64         `json:"timestamp"`
		Nonce        *big.Int       `json:"nonce"`
		PreviousHash string         `json:"previous_hash"`
		Transactions []*Transaction `json:"transactions"`
		Number       *big.Int       `json:"number"`
		Hash         string         `json:"hash"`
		Difficulty   *big.Int       `json:"difficulty"`
		TxSize       uint16         `json:"tx_size"`
	}{
		Timestamp:    b.timestamp,
		Nonce:        b.nonce,
		PreviousHash: fmt.Sprintf("%x", b.previousHash),
		Transactions: b.transactions,
		Number:       b.number,
		Hash:         fmt.Sprintf("%x", b.hash),
		Difficulty:   b.difficulty,
		TxSize:       b.txSize,
	})
}

func (b *Block) UnmarshalJSON(data []byte) error {
	var previousHash string
	var hash string
	var nonce uint64
	var number uint64
	var difficulty uint64
	v := &struct {
		Timestamp    *uint64         `json:"timestamp"`
		Nonce        *uint64            `json:"nonce"`
		PreviousHash *string         `json:"previous_hash"`
		Transactions *[]*Transaction `json:"transactions"`
		Number       *uint64            `json:"number"`
		Hash         *string         `json:"hash"`
		Difficulty   *uint64            `json:"difficulty"`
		TxSize       *uint16         `json:"tx_size"`
	}{
		Timestamp:    &b.timestamp,
		Nonce:        &nonce,
		PreviousHash: &previousHash,
		Transactions: &b.transactions,
		Number:       &number,
		Hash:         &hash,
		Difficulty:   &difficulty,
		TxSize:       &b.txSize,
	}
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	b.nonce = big.NewInt(int64(nonce))
	b.number = big.NewInt(int64(number))
	b.difficulty = big.NewInt(int64(difficulty))
	ph, _ := hex.DecodeString(*v.PreviousHash)
	copy(b.previousHash[:], ph[:32])
	h, _ := hex.DecodeString(*v.Hash)
	copy(b.hash[:], h[:32])
	return nil
}

//func (bc *Blockchain) LastBlock() *Block {
//	if len(bc.chain) == 0 {
//		return &Block{
//			nonce:        0,
//			number:       0,
//			hash:         [32]byte{},
//			previousHash: [32]byte{},
//			timestamp:    0,
//			transactions: nil,
//		}
//	} else {
//		return bc.chain[len(bc.chain)-1]
//	}
//}

func (bc *Blockchain) AddTransaction(
	sender string,
	recipient string,
	value uint64,
	senderPublicKey *ecdsa.PublicKey,
	hash string,
	s *utils.Signature) bool {
	t := NewTransaction(sender, recipient, hash, value)

	//如果是挖矿得到的奖励交易，不验证
	if sender == MINING_ACCOUNT_ADDRESS {
		bc.transactionPool = append(bc.transactionPool, t)
		return true
	}

	// 判断有没有足够的余额
	log.Printf("transaction.go sender:%s  account=%d", sender, bc.CalculateTotalAmount(sender))
	if bc.CalculateTotalAmount(sender) <= value {
		log.Printf("ERROR: %s ，你的钱包里没有足够的钱", sender)
		return false
	}

	if bc.VerifyTransactionSignature(senderPublicKey, s, t) {

		bc.transactionPool = append(bc.transactionPool, t)
		return true
	} else {
		log.Println("ERROR: 验证交易")
	}
	return false

}

func (bc *Blockchain) CreateTransaction(sender string, recipient string, value uint64,
	senderPublicKey *ecdsa.PublicKey, hash string, s *utils.Signature) bool {
	isTransacted := bc.AddTransaction(sender, recipient, value, senderPublicKey, hash, s)

	if isTransacted {
		for _, n := range bc.neighbors {
			publicKeyStr := fmt.Sprintf("%064x%064x", senderPublicKey.X.Bytes(),
				senderPublicKey.Y.Bytes())
			signatureStr := s.String()
			bt := &TransactionRequest{
				&sender, &recipient, &publicKeyStr, &value, &hash, &signatureStr}
			m, _ := json.Marshal(bt)
			buf := bytes.NewBuffer(m)
			endpoint := fmt.Sprintf("http://%s/transactions", n)
			client := &http.Client{}
			req, _ := http.NewRequest("PUT", endpoint, buf)
			resp, _ := client.Do(req)
			log.Printf("   **  **  **  CreateTransaction : %v", resp)
		}
	}

	return isTransacted
}

func (bc *Blockchain) CopyTransactionPool() []*Transaction {
	transactions := make([]*Transaction, 0)
	for _, t := range bc.transactionPool {
		transactions = append(transactions,
			NewTransaction(t.senderAddress,
				t.receiveAddress,
				t.hash,
				t.value))
	}
	return transactions
}

func bytesToBigInt(b [32]byte) *big.Int {
	bytes := b[:]
	result := new(big.Int).SetBytes(bytes)
	return result
}

func (bc *Blockchain) ValidProof(nonce int64,
	previousHash [32]byte,
	transactions []*Transaction,
	difficulty int,
) bool {
	bigi_2 := big.NewInt(2)
	bigi_256 := big.NewInt(256)
	bigi_diff := big.NewInt(int64(difficulty))

	target := new(big.Int).Exp(bigi_2, bigi_256, nil)
	target = new(big.Int).Div(target, bigi_diff)

	//zeros := "1234"
	// tmpBlock := Block{nonce: nonce, previousHash: previousHash, transactions: transactions, timestamp: time.Now().UnixNano()}
	tmpBlock := Block{nonce: big.NewInt(nonce), previousHash: previousHash, transactions: transactions, timestamp: uint64(time.Now().UnixNano())}

	//log.Printf("tmpBlock%+v", tmpBlock)
	result := bytesToBigInt(tmpBlock.Hash())
	//log.Println("guessHashStr", tmpHashStr)
	return target.Cmp(result) > 0
}

func (bc *Blockchain) getSpendTime(blockNum uint64, preBlockNum uint64) uint64 {
	if blockNum == 0 {
		return 0
	}
	return blockNum - preBlockNum
}

func (bc *Blockchain) ProofOfWork() int {
	transactions := bc.CopyTransactionPool() //选择交易？控制交易数量？
	// 获取前一个块信息
	bci := bc.Iterator()
	block, _ := bci.PreBlock()
	previousHash := block.hash
	nonce := 0

	begin := time.Now()
	for !bc.ValidProof(int64(nonce), previousHash, transactions, MINING_DIFFICULT) {
		nonce += 1
	}

	end := time.Now()
	if end.Sub(begin).Seconds() < 3e+8 {
		MINING_DIFFICULT += 32
	} else {
		if MINING_DIFFICULT >= 130000 {
			MINING_DIFFICULT -= 32
		}
	}
	//log.Printf("POW spend Time:%f", end.Sub(begin).Seconds())
	//log.Printf("POW spend Time:%f Second", seconds)
	log.Printf("POW spend Time:%f Second", end.Sub(begin).Seconds())
	log.Printf("POW spend Time:%s Diff:%v", end.Sub(begin), MINING_DIFFICULT)
	log.Printf("POW spend Time:%s", end.Sub(begin))

	return nonce
}

// 将交易池的交易打包
func (bc *Blockchain) Mining() bool {
	bc.mux.Lock()

	defer bc.mux.Unlock()

	// 此处判断交易池是否有交易，你可以不判断，打包无交易区块
	//if len(bc.transactionPool) == 0 {
	//	return false
	//}

	nonce := bc.ProofOfWork()
	log.Println("nonce成功")
	//previousHash := bc.LastBlock().Hash()
	//bc.CreateBlock(nonce, previousHash)
	block := bc.CreateBlock(nonce)
	log.Println("创建block成功")
	log.Println("action=mining, status=success")
	flag := bc.AddTransaction(MINING_ACCOUNT_ADDRESS, bc.blockchainAddress, MINING_REWARD, nil, fmt.Sprintf("%x", block.Hash()), nil)
	log.Printf("action=add_transaction, status=%v\n", flag)

	for _, n := range bc.neighbors {
		endpoint := fmt.Sprintf("http://%s/consensus", n)
		client := &http.Client{}
		req, _ := http.NewRequest("PUT", endpoint, nil)
		resp, _ := client.Do(req)
		log.Printf("%v", resp)
	}

	return true
}

func (bc *Blockchain) CalculateTotalAmount(accountAddress string) uint64 {
	var totalAmount uint64 = 0
	bci := bc.Iterator()
	for {
		block, next := bci.PreBlock()
		for _, transaction := range block.transactions {
			if accountAddress == transaction.receiveAddress {
				totalAmount = totalAmount + uint64(transaction.value)
			}
			if accountAddress == transaction.senderAddress {
				totalAmount = totalAmount - uint64(transaction.value)
			}
		}
		if !next {
			return totalAmount
		}
	}
}

func (bc *Blockchain) StartMining() {
	bc.Mining()
	// 使用time.AfterFunc函数创建了一个定时器，它在指定的时间间隔后执行bc.StartMining函数（自己调用自己）。
	_ = time.AfterFunc(time.Second*MINING_TIMER_SEC, bc.StartMining)
	color.Yellow("minetime: %v\n", time.Now())
}

//func (bc *Blockchain) GetBlockByNumber(blockid int64) (*Block, error) {
//	for _, block := range bc.chain {
//		if block.number == blockid {
//			return block, nil
//		}
//	}
//	return nil, errors.New("找不到区块")
//}

func (bc *Blockchain) GetBlockByNumber2(blockid int) (*Block, error) {
	bci := bc.Iterator()
	for {
		block, next := bci.PreBlock()
		if block.number.Cmp(big.NewInt(int64(blockid))) == 0 {
			return block, nil
		}
		if !next {
			return nil, errors.New("找不到区块")
		}
	}
}

func (bc *Blockchain) GetBlockByHash(hash string) (*Block, error) {
	if len(hash) == 0 {
		return nil, nil
	}
	bci := bc.Iterator()
	for {
		block, next := bci.PreBlock()
		if fmt.Sprintf("%x", block.hash) == hash {
			return block, nil
		}
		if !next {
			return nil, errors.New("找不到区块")
		}
	}
}

func (bc *Blockchain) GetTransactionByHash(hash string) *Transaction {
	if len(hash) == 0 {
		return nil
	}
	bci := bc.Iterator()
	for {
		block, next := bci.PreBlock()
		for _, transaction := range block.transactions {
			if transaction.hash == hash {
				return transaction
			}
		}
		if !next {
			return nil
		}
	}
}

func (bc *Blockchain) GetTransactionByUserHash(hash []byte) []*Transaction {
	if len(hash) == 0 {
		return nil
	}
	bci := bc.Iterator()
	var userTransaction []*Transaction
	for {
		block, next := bci.PreBlock()
		for _, transaction := range block.transactions {
			if transaction.receiveAddress == string(hash) || transaction.senderAddress == string(hash) {
				userTransaction = append(userTransaction, transaction)
			}
		}
		if !next {
			return userTransaction
		}
	}

}

type AmountResponse struct {
	Amount uint64 `json:"amount"`
}

func (ar *AmountResponse) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Amount uint64 `json:"amount"`
	}{
		Amount: ar.Amount,
	})
}

type Transaction struct {
	senderAddress  string
	receiveAddress string
	hash           string
	value          uint64
}

func NewTransaction(sender string, receive string, hash string, value uint64) *Transaction {
	t := Transaction{sender, receive, hash, value}
	return &t
}

func (bc *Blockchain) VerifyTransactionSignature(
	senderPublicKey *ecdsa.PublicKey, s *utils.Signature, t *Transaction) bool {
	m, _ := json.Marshal(t)
	h := sha256.Sum256([]byte(m))
	return ecdsa.Verify(senderPublicKey, h[:], s.R, s.S)
}

func (t *Transaction) Print() {
	color.Red("%s\n", strings.Repeat("~", 30))
	color.Cyan("发送地址             %s\n", t.senderAddress)
	color.Cyan("接受地址             %s\n", t.receiveAddress)
	color.Cyan("金额                 %d\n", t.value)
	color.Cyan("hash                 %d\n", t.hash)
}

func (t *Transaction) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Sender    string `json:"sender_blockchain_address"`
		Recipient string `json:"recipient_blockchain_address"`
		Value     uint64 `json:"value"`
		Hash      string `json:"hash"`
	}{
		Sender:    t.senderAddress,
		Recipient: t.receiveAddress,
		Value:     t.value,
		Hash:      t.hash,
	})
}

func (t *Transaction) UnmarshalJSON(data []byte) error {
	v := &struct {
		Sender    *string `json:"sender_blockchain_address"`
		Recipient *string `json:"recipient_blockchain_address"`
		Hash      *string `json:"hash"`
		Value     *uint64 `json:"value"`
	}{
		Sender:    &t.senderAddress,
		Recipient: &t.receiveAddress,
		Hash:      &t.hash,
		Value:     &t.value,
	}
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	return nil
}

func (t *Transaction) Hash() [32]byte {
	m, _ := json.Marshal(t)
	return sha256.Sum256([]byte(m))
}

func (bc *Blockchain) ValidChain(chain []*Block) bool {
	preBlock := chain[0]
	currentIndex := 1
	for currentIndex < len(chain) {
		b := chain[currentIndex]
		if b.previousHash != preBlock.Hash() {
			return false
		}

		if !bc.ValidProof(b.Nonce(), b.PreviousHash(), b.Transactions(), MINING_DIFFICULT) {
			return false
		}

		preBlock = b
		currentIndex += 1
	}
	return true
}

func (bc *Blockchain) ResolveConflicts() bool {
	var longestChain []*Block = nil
	maxLength := len(bc.chain)

	for _, n := range bc.neighbors {
		endpoint := fmt.Sprintf("http://%s/chain", n)
		resp, err := http.Get(endpoint)
		if err != nil {
			color.Red("                 错误 ：ResolveConflicts GET请求")
			return false
		} else {
			color.Green("                正确 ：ResolveConflicts  GET请求")
		}
		if resp.StatusCode == 200 {
			var bcResp Blockchain
			decoder := json.NewDecoder(resp.Body)
			err1 := decoder.Decode(&bcResp)

			if err1 != nil {
				color.Red("                 错误 ：ResolveConflicts Decode")
				return false
			} else {
				color.Green("                正确 ：ResolveConflicts  Decode")
			}

			chain := bcResp.Chain()
			color.Cyan("   ResolveConflicts   chain len:%d ", len(chain))
			if len(chain) > maxLength && bc.ValidChain(chain) {
				maxLength = len(chain)
				longestChain = chain
			}
		}
	}

	color.Cyan("   ResolveConflicts   longestChain len:%d ", len(longestChain))

	if longestChain != nil {
		bc.chain = longestChain
		log.Printf("Resovle confilicts replaced")
		return true
	}
	log.Printf("Resovle conflicts not replaced")
	return false
}

type TransactionRequest struct {
	SenderBlockchainAddress    *string `json:"sender_blockchain_address"`
	RecipientBlockchainAddress *string `json:"recipient_blockchain_address"`
	SenderPublicKey            *string `json:"sender_public_key"`
	Value                      *uint64 `json:"value"`
	Hash                       *string `json:"hash"`
	Signature                  *string `json:"signature"`
}

func (tr *TransactionRequest) Validate() bool {
	if tr.SenderBlockchainAddress == nil ||
		tr.RecipientBlockchainAddress == nil ||
		tr.SenderPublicKey == nil ||
		tr.Value == nil ||
		tr.Signature == nil {
		return false
	}
	return true
}
