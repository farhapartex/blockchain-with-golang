package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Wallet struct {
	PrivateKey *ecdsa.PrivateKey
	PublicKey  []byte
	Address    string
}

type Transaction struct {
	ID        string  `json:"id"`
	From      string  `json:"from"`
	To        string  `json:"to"`
	Amount    float64 `json:"amount"`
	Signature []byte  `json:"signature"`
	Timestamp int64   `json:"timestamp"`
}

type Block struct {
	Index        int            `json:"index"`
	Timestamp    int64          `json:"timestamp"`
	PreviousHash string         `json:"previous_hash"`
	Hash         string         `json:"hash"`
	Transactions []*Transaction `json:"transactions"`
	Nonce        int            `json:"nonce"`
	Miner        string         `json:"miner"` // Address of the miner who mined this block
}

type Peer struct {
	// Peer: Represents a node in the blockchain network
	ID      string `json:"id"`
	Address string `json:"address"` // Network address of the peer
	Active  bool   `json:"active"`
}

type Node struct {
	// Node: Represents a node in the blockchain network
	ID          string           `json:"id"`            // Unique identifier for the node
	Address     string           `json:"address"`       // Network address of the node
	Port        int              `json:"port"`          // Port number for the node
	Blockchain  []*Block         `json:"blockchain"`    // The blockchain maintained by this node
	Mempool     []*Transaction   `json:"mempool"`       // Transactions that are not yet included in a block
	Peers       map[string]*Peer `json:"peers"`         // List of peers connected to this node
	Wallet      *Wallet          `json:"wallet"`        // Wallet associated with the node
	IsBootstrap bool             `json:"is_bootstrap"`  // Indicates if this node is a bootstrap node
	MinigReward float64          `json:"mining_reward"` // Reward for mining a block
	mutex       sync.Mutex
	Difficulty  int `json:"difficulty"` // Difficulty level for mining blocks
}

type NetworkMessage struct {
	Type   string      `json:"type"` // Type of message (e.g., "transaction", "block", "wallet")
	Data   interface{} `json:"data"` // Data associated with the message (e.g., transaction data, block data, wallet info)
	From   string      `json:"from"`
	NodeID string      `json:"node_id"` // Unique identifier for the node sending the message
}

func NewWallet() *Wallet {
	// NewWallet: Creates a new wallet with a generated ECDSA key pair
	// and derives the public key and address from it.
	// Returns a pointer to the Wallet struct containing the private key,
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	if err != nil {
		panic(err)
	}

	pubKey := append(private.PublicKey.X.Bytes(), private.PublicKey.Y.Bytes()...)
	address := fmt.Sprintf("%x", sha256.Sum256(pubKey))[:20]

	return &Wallet{
		PrivateKey: private,
		PublicKey:  pubKey,
		Address:    address,
	}
}

func (w *Wallet) Sign(data []byte) []byte {
	hash := sha256.Sum256(data) // Hash the data to be signed
	r, s, err := ecdsa.Sign(rand.Reader, w.PrivateKey, hash[:])
	// Sign the hash with the private key and return r and s values where r = the x-coordinate of the signature and s = the y-coordinate of the signature
	if err != nil {
		panic(err)
	}

	return append(r.Bytes(), s.Bytes()...) // Return the signature as concatenated r and s values
}

func (w *Wallet) GetBalance(blockchain []*Block) float64 {
	// GetBalance: Calculates the balance of the wallet by iterating through the blockchain
	// and summing the amounts of transactions that involve the wallet's address.
	// It returns the total balance as a float64 value.
	balance := 0.0

	for _, block := range blockchain {
		for _, tx := range block.Transactions {
			if tx.To == w.Address {
				balance += tx.Amount
			}

			if tx.From == w.Address {
				balance -= tx.Amount
			}
		}
	}

	return balance
}

func (tx *Transaction) calculateHash() string {
	record := tx.From + tx.To + fmt.Sprintf("%.2f", tx.Amount) + strconv.FormatInt(tx.Timestamp, 10)
	hash := sha256.Sum256([]byte(record))

	return hex.EncodeToString(hash[:])
}

func (tx *Transaction) signTransaction(wallet *Wallet) {
	if wallet.Address != tx.From {
		panic("You cannot sign a transaction for another wallet")
	}

	dataToSign := []byte(tx.ID)
	tx.Signature = wallet.Sign(dataToSign)
}

func (tx *Transaction) isValid() bool {
	if tx.From == "" { // Mining reward
		return true
	}
	return len(tx.Signature) > 0 // Simplified validation
}

func NewTransaction(from string, to string, amount float64, wallet *Wallet) *Transaction {
	// NewTransaction: Creates a new transaction with the specified parameters.
	// It calculates the transaction ID based on its content and signs it if a wallet is provided.
	if from == "" || to == "" || amount <= 0 {
		panic("Invalid transaction parameters")
	}
	if from == to {
		panic("Transaction cannot be sent to the same address")
	}
	tx := Transaction{
		From:      from,
		To:        to,
		Amount:    amount,
		Timestamp: time.Now().Unix(),
	}

	tx.ID = tx.calculateHash() // Calculate the transaction ID based on its content
	if wallet != nil && wallet.Address == from {
		tx.signTransaction(wallet) // Sign the transaction if a wallet is provided
	}

	return &tx
}

func (b *Block) calculateHash() string {
	// calculateHash: Calculates the hash of the block based on its content.
	// It includes the block's index, timestamp, previous hash, transaction hashes, nonce, and miner address.
	// It returns the hash as a hexadecimal string.
	txHashes := ""
	for _, tx := range b.Transactions {
		txHashes += tx.ID
	}

	record := strconv.Itoa(b.Index) + strconv.FormatInt(b.Timestamp, 10) + b.PreviousHash + txHashes + strconv.Itoa(b.Nonce) + b.Miner
	hash := sha256.Sum256([]byte(record)) // Create a record string that includes the block's index, timestamp, previous hash, transaction hashes, nonce, and miner address
	return hex.EncodeToString(hash[:])    // Calculate the hash of the block based on its content
}

func (b *Block) mineBlock(difficuly int) {
	target := strings.Repeat("0", difficuly)

	fmt.Printf("Mining block %d...\n", b.Index)

	for !strings.HasPrefix(b.Hash, target) {
		b.Nonce++
		b.Hash = b.calculateHash()
	}

	fmt.Printf("Block mined! Hash: %s\n", b.Hash)
}

func NewNode(port int, isBootstrep bool, miningReward float64, difficulty int) *Node {
	// NewNode: Creates a new node with the specified parameters.
	// It initializes the node's blockchain with an initial block and sets up a wallet for the node.
	// It returns a pointer to the Node struct representing the new node.
	// port: The port number for the node to listen on
	// isBootstrep: Indicates whether the node is a bootstrap node
	// miningReward: The reward for mining a block

	if port <= 0 {
		panic("Port number must be greater than 0")
	}
	if miningReward <= 0 {
		panic("Mining reward must be greater than 0")
	}
	if difficulty <= 0 {
		panic("Difficulty must be greater than 0")
	}
	wallet := NewWallet() // Create a new wallet for the node

	node := Node{
		ID:          fmt.Sprint(time.Now().UnixNano()),        // Unique identifier for the node based on current time
		Address:     fmt.Sprintf("http://localhost:%d", port), // Network address of the node
		Port:        port,
		Blockchain:  []*Block{},
		Mempool:     []*Transaction{}, // Initialize an empty mempool for the node. Mempool is a collection of transactions that are waiting to be included in a block.
		Peers:       make(map[string]*Peer),
		Wallet:      wallet,       // Assign the created wallet to the node
		IsBootstrap: isBootstrep,  // Set whether the node is a bootstrap node
		MinigReward: miningReward, // Set the mining reward for the node
		Difficulty:  difficulty,
	}

	initialBlock := Block{
		Index:        0,
		Timestamp:    time.Now().Unix(),
		PreviousHash: "0",
		Nonce:        0,
		Miner:        node.ID, // Set the miner to the node's ID
		Transactions: []*Transaction{},
	}

	initialBlock.Hash = initialBlock.calculateHash()         // Calculate the hash of the initial block
	node.Blockchain = append(node.Blockchain, &initialBlock) // Add the initial block to the node's blockchain
	return &node
}

func (n *Node) StartServer() {
	// StartServer: Starts the node's server to listen for incoming connections and handle network messages.
	// This function should be implemented to set up the HTTP server and handle requests.
	mux := http.NewServeMux()
	mux.HandleFunc("/", n.handleHome) // Handle the home route
	mux.HandleFunc("/status", n.handleStatus)
	mux.HandleFunc("/peers", n.handlePeers)
	mux.HandleFunc("/join", n.handleJoin)
	mux.HandleFunc("/blockchain", n.handleBlockchain)
	mux.HandleFunc("/transaction", n.handleTransaction)
	mux.HandleFunc("/mine", n.handleMine)
	mux.HandleFunc("/balance", n.handleBalance)
	mux.HandleFunc("/broadcast", n.handleBroadcast)
	mux.HandleFunc("/sync", n.handleSync)

	// server := &http.Server{
	// 	Addr:    n.Address, // Set the server address
	// 	Handler: mux,       // Set the request handler
	// }

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", n.Port), mux))
}

func (n *Node) handleHome(w http.ResponseWriter, r *http.Request) {
	n.mutex.Lock() // Lock the mutex to ensure thread-safe access to the node's data
	// handleHome: Handles the home route of the node's server.
	// It responds with a simple message indicating that the node is running.
	defer n.mutex.Unlock()

	// handleHome: Handles the home route of the node's server.
	// It responds with a simple message indicating that the node is running.
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Node %s is running at %s\n", n.ID, n.Address)
}

func (n *Node) handleStatus(w http.ResponseWriter, r *http.Request) {
	n.mutex.Lock() // Lock the mutex to ensure thread-safe access to the node's data
	defer n.mutex.Unlock()
	status := map[string]interface{}{
		"node_id":           n.ID,
		"address":           n.Address,
		"wallet_address":    n.Wallet.Address,
		"is_bootstrap":      n.IsBootstrap,
		"peers_count":       len(n.Peers),
		"blockchain_length": len(n.Blockchain),
		"mempool_length":    len(n.Mempool),
		"mining_reward":     n.MinigReward,
		"difficulty":        n.Difficulty,
		"balance":           n.Wallet.GetBalance(n.Blockchain),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func (n *Node) handlePeers(w http.ResponseWriter, r *http.Request) {
	n.mutex.Lock() // Lock the mutex to ensure thread-safe access to the node's data
	defer n.mutex.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(n.Peers)
}

func (n *Node) handleJoin(w http.ResponseWriter, r *http.Request) {
	peerAddress := r.URL.Query().Get("peer")
	if peerAddress == "" {
		http.Error(w, "Missing peer address", http.StatusBadRequest)
		return
	}

	success := n.connectToPeer(peerAddress)
	if success {
		n.syncBlockchain()
	} else {
		http.Error(w, "Failed to connect to peer", http.StatusInternalServerError)
	}
}

func (n *Node) handleBlockchain(w http.ResponseWriter, r *http.Request) {
	n.mutex.Lock() // Lock the mutex to ensure thread-safe access to the node's data
	defer n.mutex.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(n.Blockchain) // Encode the blockchain as JSON and send it in the response
}

func (n *Node) handleTransaction(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		To     string  `json:"to"`
		Amount float64 `json:"amount"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	balance := n.Wallet.GetBalance(n.Blockchain)
	if req.Amount <= 0 || req.To == "" || req.Amount > balance {
		http.Error(w, "Invalid transaction parameters", http.StatusBadRequest)
		return
	}

	tx := NewTransaction(n.Wallet.Address, req.To, req.Amount, n.Wallet)

	n.mutex.Lock()
	n.Mempool = append(n.Mempool, tx) // Add the transaction to the node's mempool
	n.mutex.Unlock()

	n.broadcastTransaction(tx) // Broadcast the transaction to connected peers
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated) // Set the response status to Created (201)
	json.NewEncoder(w).Encode(tx)     // Encode the transaction as JSON and send it in the response
}

func (n *Node) handleMine(w http.ResponseWriter, r *http.Request) {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	// if len(n.Mempool) == 0 {
	// 	http.Error(w, "No transactions to mine", http.StatusBadRequest)
	// 	return
	// }

	// create reward transaction to mine
	tx := Transaction{
		ID:        fmt.Sprintf("reward_%d_%d", time.Now().UnixNano(), len(n.Blockchain)),
		From:      "",
		To:        n.Wallet.Address,
		Amount:    n.MinigReward,
		Timestamp: time.Now().Unix(),
	}

	allTx := append([]*Transaction{&tx}, n.Mempool...)

	prevBlock := n.Blockchain[len(n.Blockchain)-1]
	newBlock := &Block{
		Index:        prevBlock.Index + 1,
		Timestamp:    time.Now().Unix(),
		PreviousHash: prevBlock.Hash,
		Transactions: allTx,
		Nonce:        0,
		Miner:        n.ID,
	}

	newBlock.mineBlock(n.Difficulty)
	n.Blockchain = append(n.Blockchain, newBlock)

	n.Mempool = []*Transaction{}

	go n.broadcastBlock(newBlock)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(newBlock) // Encode the newly mined block as JSON and send it in the response
}

func (n *Node) handleBalance(w http.ResponseWriter, r *http.Request) {
	address := r.URL.Query().Get("address")
	if address == "" {
		address = n.Wallet.Address
	}

	balance := n.calculateBalance(address)

	response := map[string]interface{}{
		"address": address,
		"balance": balance,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (n *Node) handleBroadcast(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var msg NetworkMessage
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	n.processNetworkMessage(&msg)
	w.WriteHeader(http.StatusOK)
}

func (n *Node) handleSync(w http.ResponseWriter, r *http.Request) {
	n.syncBlockchain()
	fmt.Fprintf(w, "Blockchain synchronized")
}

func (n *Node) connectToPeer(peerAddress string) bool {
	// Get peer info
	resp, err := http.Get(peerAddress + "/status")
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	var peerStatus map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&peerStatus); err != nil {
		return false
	}

	peerID := peerStatus["node_id"].(string)

	// Add to peers list
	n.mutex.Lock()
	n.Peers[peerID] = &Peer{
		ID:      peerID,
		Address: peerAddress,
		Active:  true,
	}
	n.mutex.Unlock()

	// Announce ourselves to the peer
	announcement := NetworkMessage{
		Type:   "peer_announcement",
		From:   n.Address,
		NodeID: n.ID,
		Data: map[string]string{
			"address": n.Address,
			"node_id": n.ID,
		},
	}

	n.sendMessageToPeer(peerAddress, &announcement)
	return true
}

func (n *Node) broadcastTransaction(tx *Transaction) {
	msg := NetworkMessage{
		Type:   "new_transaction",
		From:   n.Address,
		NodeID: n.ID,
		Data:   tx,
	}

	n.broadcastToPeers(&msg)
}

func (n *Node) broadcastBlock(block *Block) {
	msg := NetworkMessage{
		Type:   "new_block",
		From:   n.Address,
		NodeID: n.ID,
		Data:   block,
	}

	n.broadcastToPeers(&msg)
}

func (n *Node) broadcastToPeers(msg *NetworkMessage) {
	n.mutex.Lock()
	peers := make([]*Peer, 0, len(n.Peers))
	for _, peer := range n.Peers {
		if peer.Active {
			peers = append(peers, peer)
		}
	}
	n.mutex.Unlock()

	for _, peer := range peers {
		go n.sendMessageToPeer(peer.Address, msg)
	}
}

func (n *Node) sendMessageToPeer(peerAddress string, msg *NetworkMessage) {
	jsonData, err := json.Marshal(msg)
	if err != nil {
		return
	}

	_, err = http.Post(peerAddress+"/broadcast", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		// Mark peer as inactive on error
		n.mutex.Lock()
		for _, peer := range n.Peers {
			if peer.Address == peerAddress {
				peer.Active = false
			}
		}
		n.mutex.Unlock()
	}
}

func (n *Node) processNetworkMessage(msg *NetworkMessage) {
	switch msg.Type {
	case "peer_announcement":
		n.handlePeerAnnouncement(msg)
	case "new_transaction":
		n.handleNewTransaction(msg)
	case "new_block":
		n.handleNewBlock(msg)
	}
}

func (n *Node) handlePeerAnnouncement(msg *NetworkMessage) {
	data := msg.Data.(map[string]interface{})
	peerID := data["node_id"].(string)
	peerAddress := data["address"].(string)

	n.mutex.Lock()
	n.Peers[peerID] = &Peer{
		ID:      peerID,
		Address: peerAddress,
		Active:  true,
	}
	n.mutex.Unlock()

	fmt.Printf("🤝 New peer connected: %s (%s)\n", peerID, peerAddress)
}

func (n *Node) handleNewTransaction(msg *NetworkMessage) {
	txData, _ := json.Marshal(msg.Data)
	var tx Transaction
	json.Unmarshal(txData, &tx)

	if tx.isValid() && !n.transactionExists(&tx) {
		n.mutex.Lock()
		n.Mempool = append(n.Mempool, &tx)
		n.mutex.Unlock()

		fmt.Printf("📨 Received transaction: %s → %s (%.2f coins)\n",
			tx.From[:8], tx.To[:8], tx.Amount)
	}
}

func (n *Node) handleNewBlock(msg *NetworkMessage) {
	blockData, _ := json.Marshal(msg.Data)
	var block Block
	json.Unmarshal(blockData, &block)

	if n.isValidBlock(&block) {
		n.mutex.Lock()
		n.Blockchain = append(n.Blockchain, &block)
		// Remove mined transactions from mempool
		n.removeMinedTransactions(&block)
		n.mutex.Unlock()

		fmt.Printf("📦 Received new block %d from %s (Hash: %s)\n",
			block.Index, block.Miner, block.Hash[:20]+"...")
	}
}

func (n *Node) syncBlockchain() {
	n.mutex.Lock()
	peers := make([]*Peer, 0, len(n.Peers))
	for _, peer := range n.Peers {
		if peer.Active {
			peers = append(peers, peer)
		}
	}
	n.mutex.Unlock()

	for _, peer := range peers {
		resp, err := http.Get(peer.Address + "/blockchain")
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		var peerBlockchain []*Block
		if err := json.NewDecoder(resp.Body).Decode(&peerBlockchain); err != nil {
			continue
		}

		if len(peerBlockchain) > len(n.Blockchain) && n.isValidChain(peerBlockchain) {
			n.mutex.Lock()
			n.Blockchain = peerBlockchain
			n.mutex.Unlock()
			fmt.Printf("🔄 Blockchain updated from peer %s (length: %d)\n", peer.ID, len(peerBlockchain))
			break
		}
	}
}

func (n *Node) calculateBalance(address string) float64 {
	balance := 0.0
	for _, block := range n.Blockchain {
		for _, tx := range block.Transactions {
			if tx.To == address {
				balance += tx.Amount
			}
			if tx.From == address {
				balance -= tx.Amount
			}
		}
	}
	return balance
}

func (n *Node) transactionExists(tx *Transaction) bool {
	for _, memTx := range n.Mempool {
		if memTx.ID == tx.ID {
			return true
		}
	}
	return false
}

func (n *Node) isValidBlock(block *Block) bool {
	if len(n.Blockchain) == 0 {
		return false
	}

	lastBlock := n.Blockchain[len(n.Blockchain)-1]
	return block.Index == lastBlock.Index+1 &&
		block.PreviousHash == lastBlock.Hash &&
		strings.HasPrefix(block.Hash, strings.Repeat("0", n.Difficulty))
}

func (n *Node) isValidChain(chain []*Block) bool {
	for i := 1; i < len(chain); i++ {
		if chain[i].Index != chain[i-1].Index+1 ||
			chain[i].PreviousHash != chain[i-1].Hash {
			return false
		}
	}
	return true
}

func (n *Node) removeMinedTransactions(block *Block) {
	for _, minedTx := range block.Transactions {
		for i, mempoolTx := range n.Mempool {
			if mempoolTx.ID == minedTx.ID {
				n.Mempool = append(n.Mempool[:i], n.Mempool[i+1:]...)
				break
			}
		}
	}
}

func main() {
	miningReqrd := 10.0
	difficulty := 4

	bootstrap := NewNode(8001, true, miningReqrd, difficulty)
	node2 := NewNode(8002, false, miningReqrd, difficulty)
	node3 := NewNode(8003, false, miningReqrd, difficulty)

	go bootstrap.StartServer()
	go node2.StartServer()
	go node3.StartServer()
	time.Sleep(6 * time.Second) // Wait for servers to start
	fmt.Println("Blockchain network nodes are running...")

	// node2.connectToPeer("http://localhost:8001")
	// node3.connectToPeer("http://localhost:8001")

	fmt.Println("Network is ready! All nodes connected.")
	fmt.Println("Try mining some blocks and sending transactions between nodes!")
	select {} // Keep the main function running indefinitely
}
