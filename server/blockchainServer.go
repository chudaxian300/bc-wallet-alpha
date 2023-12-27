package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strconv"
	"xlxblockchain/block"
	"xlxblockchain/utils"

	"github.com/fatih/color"
)

var cache map[string]*block.Blockchain = make(map[string]*block.Blockchain)

type BlockchainServer struct {
	port uint16
}

func NewBlockchainServer(port uint16) *BlockchainServer {
	return &BlockchainServer{port}
}

func (bcs *BlockchainServer) Port() uint16 {
	return bcs.port
}

// func handle_HelloWorld(w http.ResponseWriter, req *http.Request) {
// 	io.WriteString(w, "<h1>Hello, World!区块链学院</h1>")
// }

func (bcs *BlockchainServer) GetBlockchain() *block.Blockchain {
	bc, ok := cache["blockchain"]
	if !ok {
		// minersWallet := wallet.NewWallet()
		// NewBlockchain与以前的方法不一样,增加了地址和端口2个参数,是为了区别不同的节点
		bc = block.NewBlockchain(bcs.Port())
		cache["blockchain"] = bc
		return bc
	} else {
		return bc
	}
}

func (bcs *BlockchainServer) GetChain(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodGet:
		w.Header().Add("Content-Type", "application/json")
		bc := bcs.GetBlockchain()
		m, _ := bc.MarshalJSON()
		io.WriteString(w, string(m[:]))
	default:
		log.Printf("ERROR: Invalid HTTP Method")

	}
}

func (bcs *BlockchainServer) Transactions(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodGet:
		{
			// Get:显示交易池的内容，Mine成功后清空交易池
			w.Header().Add("Content-Type", "application/json")
			bc := bcs.GetBlockchain()

			transactions := bc.TransactionPool()
			m, _ := json.Marshal(struct {
				Transactions []*block.Transaction `json:"transactions"`
				Length       int                  `json:"length"`
			}{
				Transactions: transactions,
				Length:       len(transactions),
			})
			io.WriteString(w, string(m[:]))
		}
	case http.MethodPost:
		{
			log.Printf("\n\n\n")
			log.Println("接受到wallet发送的交易")
			decoder := json.NewDecoder(req.Body)
			var t block.TransactionRequest
			err := decoder.Decode(&t)
			if err != nil {
				log.Printf("ERROR: %v", err)
				io.WriteString(w, string(utils.JsonStatus("Decode Transaction失败")))
				return
			}

			log.Println("发送人公钥SenderPublicKey:", *t.SenderPublicKey)
			log.Println("接收人地址RecipientBlockchainAddress:", *t.RecipientBlockchainAddress)
			log.Println("金额Value:", *t.Value)
			log.Println("交易Hash:", *t.Hash)
			log.Println("交易Signature:", *t.Signature)

			if !t.Validate() {
				log.Println("ERROR: missing field(s)")
				io.WriteString(w, string(utils.JsonStatus("fail")))
				return
			}

			publicKey := utils.PublicKeyFromString(*t.SenderPublicKey)
			signature := utils.SignatureFromString(*t.Signature)
			bc := bcs.GetBlockchain()

			isCreated := bc.CreateTransaction(*t.SenderBlockchainAddress,
				*t.RecipientBlockchainAddress, uint64(int64(*t.Value)), publicKey, *t.Hash, signature)

			w.Header().Add("Content-Type", "application/json")
			var m []byte
			if !isCreated {
				w.WriteHeader(http.StatusBadRequest)
				m = utils.JsonStatus("fail[from:blockchainServer]")
			} else {
				w.WriteHeader(http.StatusCreated)
				m = utils.JsonStatus("success[from:blockchainServer]")
			}
			io.WriteString(w, string(m))

		}
	case http.MethodPut:
		// PUT方法 用于在另据节点同步交易
		decoder := json.NewDecoder(req.Body)
		var t block.TransactionRequest
		err := decoder.Decode(&t)
		if err != nil {
			log.Printf("ERROR: %v", err)
			io.WriteString(w, string(utils.JsonStatus("fail")))
			return
		}
		if !t.Validate() {
			log.Println("ERROR: missing field(s)")
			io.WriteString(w, string(utils.JsonStatus("fail")))
			return
		}
		publicKey := utils.PublicKeyFromString(*t.SenderPublicKey)
		signature := utils.SignatureFromString(*t.Signature)
		bc := bcs.GetBlockchain()

		isUpdated := bc.AddTransaction(*t.SenderBlockchainAddress,
			*t.RecipientBlockchainAddress, *t.Value, publicKey, *t.Hash, signature)

		w.Header().Add("Content-Type", "application/json")
		var m []byte
		if !isUpdated {
			w.WriteHeader(http.StatusBadRequest)
			m = utils.JsonStatus("fail")
		} else {
			m = utils.JsonStatus("success")
		}
		io.WriteString(w, string(m))
	case http.MethodDelete:
		bc := bcs.GetBlockchain()
		bc.ClearTransactionPool()
		io.WriteString(w, string(utils.JsonStatus("success")))
	default:
		log.Println("ERROR: Invalid HTTP Method")
		w.WriteHeader(http.StatusBadRequest)
	}
}

func (bcs *BlockchainServer) Mine(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodGet:
		bc := bcs.GetBlockchain()
		isMined := bc.Mining()

		var m []byte
		if !isMined {
			w.WriteHeader(http.StatusBadRequest)
			m = utils.JsonStatus("挖矿失败[from:Mine]")
		} else {
			m = utils.JsonStatus("挖矿成功[from:Mine]")
		}
		w.Header().Add("Content-Type", "application/json")
		io.WriteString(w, string(m))
	default:
		log.Println("ERROR: Invalid HTTP Method")
		w.WriteHeader(http.StatusBadRequest)
	}
}

func (bcs *BlockchainServer) StartMine(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodGet:
		bc := bcs.GetBlockchain()
		bc.StartMining()

		m := utils.JsonStatus("success")
		w.Header().Add("Content-Type", "application/json")
		io.WriteString(w, string(m))
	default:
		log.Println("ERROR: Invalid HTTP Method")
		w.WriteHeader(http.StatusBadRequest)
	}
}

func (bcs *BlockchainServer) Amount(w http.ResponseWriter, req *http.Request) {

	switch req.Method {
	case http.MethodPost:

		var data map[string]interface{}
		// 解析JSON数据

		err := json.NewDecoder(req.Body).Decode(&data)
		if err != nil {
			http.Error(w, "无法解析JSON数据", http.StatusBadRequest)
			return
		}
		// 获取JSON字段的值
		blockchainAddress := data["blockchain_address"].(string)

		color.Green("查询账户: %s 余额请求", blockchainAddress)

		amount := bcs.GetBlockchain().CalculateTotalAmount(blockchainAddress)

		ar := &block.AmountResponse{Amount: amount}
		m, _ := ar.MarshalJSON()

		w.Header().Add("Content-Type", "application/json")
		io.WriteString(w, string(m[:]))

	default:
		log.Printf("ERROR: Invalid HTTP Method")
		w.WriteHeader(http.StatusBadRequest)
	}
}

func (bcs *BlockchainServer) Consensus(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodPut:
		color.Cyan("####################Consensus###############")
		bc := bcs.GetBlockchain()
		replaced := bc.ResolveConflicts()
		color.Red("[共识]Consensus replaced :%v\n", replaced)
		w.Header().Add("Content-Type", "application/json")
		if replaced {
			io.WriteString(w, string(utils.JsonStatus("success")))
		} else {
			io.WriteString(w, string(utils.JsonStatus("fail")))
		}
	default:
		log.Printf("ERROR: Invalid HTTP Method")
		w.WriteHeader(http.StatusBadRequest)
	}
}

func (bcs *BlockchainServer) GetBlockByNumber(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodPost:
		var data map[string]interface{}
		// 解析JSON数据

		err := json.NewDecoder(req.Body).Decode(&data)
		if err != nil {
			http.Error(w, "无法解析JSON数据", http.StatusBadRequest)
			return
		}
		// 获取JSON字段的值
		blockNumber, _ := strconv.Atoi(data["number"].(string))
		color.Green("查询区块: %s 区块号请求", blockNumber)
		blockchain := bcs.GetBlockchain()
		number, err := blockchain.GetBlockByNumber2(blockNumber)
		if err != nil {
			http.Error(w, "无法根据区块号查询数据", http.StatusInternalServerError)
			return
		}
		marshalJSON, _ := number.MarshalJSON()
		w.Header().Add("Content-Type", "application/json")
		io.WriteString(w, string(marshalJSON[:]))
	default:
		log.Printf("ERROR: Invalid HTTP Method")
		w.WriteHeader(http.StatusBadRequest)
	}
}

func (bcs *BlockchainServer) GetBlockByHash(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodPost:
		var data map[string]interface{}
		// 解析JSON数据

		err := json.NewDecoder(req.Body).Decode(&data)
		if err != nil {
			http.Error(w, "无法解析JSON数据", http.StatusBadRequest)
			return
		}
		// 获取JSON字段的值
		blockHash := data["hash"].(string)
		color.Green("查询区块: %s 区块哈希请求", blockHash)
		blockchain := bcs.GetBlockchain()
		number, err := blockchain.GetBlockByHash(blockHash)
		if err != nil {
			http.Error(w, "无法根据区块哈希查询数据", http.StatusInternalServerError)
			return
		}
		marshalJSON, _ := number.MarshalJSON()
		w.Header().Add("Content-Type", "application/json")
		io.WriteString(w, string(marshalJSON[:]))
	default:
		log.Printf("ERROR: Invalid HTTP Method")
		w.WriteHeader(http.StatusBadRequest)
	}
}

func (bcs *BlockchainServer) GetTransactionByHash(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodPost:
		var data map[string]interface{}
		// 解析JSON数据

		err := json.NewDecoder(req.Body).Decode(&data)
		if err != nil {
			http.Error(w, "无法解析JSON数据", http.StatusBadRequest)
			return
		}
		// 获取JSON字段的值
		blockHash := data["hash"].(string)
		color.Green("查询交易: %s 交易哈希请求", blockHash)
		blockchain := bcs.GetBlockchain()
		transaction := blockchain.GetTransactionByHash(blockHash)
		if transaction == nil {
			http.Error(w, "无法根据区块哈希查询数据", http.StatusInternalServerError)
			return
		}
		marshalJSON, _ := transaction.MarshalJSON()
		w.Header().Add("Content-Type", "application/json")
		io.WriteString(w, string(marshalJSON[:]))
	default:
		log.Printf("ERROR: Invalid HTTP Method")
		w.WriteHeader(http.StatusBadRequest)
	}
}

func (bcs *BlockchainServer) GetTransactionByUserHash(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodPost:
		var data map[string]interface{}
		// 解析JSON数据

		err := json.NewDecoder(req.Body).Decode(&data)
		if err != nil {
			http.Error(w, "无法解析JSON数据", http.StatusBadRequest)
			return
		}
		// 获取JSON字段的值
		blockHash := data["hash"].(string)
		color.Green("查询交易: %s 用户交易哈希请求", blockHash)
		blockchain := bcs.GetBlockchain()
		transactions := blockchain.GetTransactionByUserHash([]byte(blockHash))
		resp := map[string]interface{}{
			"transactions": transactions,
		}
		marshal, _ := json.Marshal(resp)
		w.Header().Add("Content-Type", "application/json")
		io.WriteString(w, string(marshal))
	default:
		log.Printf("ERROR: Invalid HTTP Method")
		w.WriteHeader(http.StatusBadRequest)
	}
}

func (bcs *BlockchainServer) Run() {
	bcs.GetBlockchain().Run()

	http.HandleFunc("/", bcs.GetChain)

	http.HandleFunc("/transactions", bcs.Transactions) //GET 方式和  POST方式
	http.HandleFunc("/mine", bcs.Mine)
	http.HandleFunc("/mine/start", bcs.StartMine)
	http.HandleFunc("/amount", bcs.Amount)
	http.HandleFunc("/consensus", bcs.Consensus)
	http.HandleFunc("/block/number", bcs.GetBlockByNumber)
	http.HandleFunc("/block/hash", bcs.GetBlockByHash)
	http.HandleFunc("/transactions/hash", bcs.GetTransactionByHash)
	http.HandleFunc("/transactions/user/hash", bcs.GetTransactionByUserHash)
	log.Fatal(http.ListenAndServe(":"+strconv.Itoa(int(bcs.Port())), nil))

}
