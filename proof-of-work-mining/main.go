package main

import (
	"crypto/sha256"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type Block struct {
	Index        int
	Timestamp    int64
	Data         string
	PreviousHash string
	Hash         string
	Nonce        int // Number used in proof-of-work
}

type Blockchain struct {
	blocks     []*Block
	difficulty int // Difficulty level for proof-of-work
}

func (b *Block) calculateHash() string {
	record := strconv.Itoa(b.Index) + strconv.FormatInt(b.Timestamp, 10) + b.Data + b.PreviousHash + strconv.Itoa(b.Nonce)

	h := sha256.New()
	h.Write([]byte(record))
	hashed := h.Sum(nil)

	return fmt.Sprintf("%x", hashed)
}

func (b *Block) mineBlock(difficulty int) {
	target := strings.Repeat("0", difficulty)
	fmt.Println("Mining block ...", b.Index)

	startTime := time.Now()

	for {
		b.Hash = b.calculateHash()

		if strings.HasPrefix(b.Hash, target) {
			duration := time.Since(startTime)
			fmt.Println("MINED \n")
			fmt.Println("Nonce: ", b.Nonce)
			fmt.Println("Hash: ", b.Hash)
			fmt.Printf("Time taken: %v\n", duration)
			break
		}

		b.Nonce++

		if b.Nonce%100000 == 0 {
			fmt.Printf("\nNonce: %d, Hash: %s\n\n", b.Nonce, b.Hash)
		}
	}
}

func generateGenesisBlock() *Block {
	block := Block{
		Index:        0,
		Timestamp:    time.Now().Unix(),
		Data:         "Genesis Block",
		PreviousHash: "",
		Hash:         "",
		Nonce:        0,
	}

	return &block
}

func generateBlock(oldBlock *Block, data string) *Block {
	block := Block{
		Index:        oldBlock.Index + 1,
		Timestamp:    time.Now().Unix(),
		Data:         data,
		PreviousHash: oldBlock.Hash,
	}

	block.Hash = block.calculateHash()

	return &block
}

func NewBlockchain(difficulty int) *Blockchain {
	initialBlock := generateGenesisBlock()

	initialBlock.mineBlock(difficulty)

	return &Blockchain{
		blocks:     []*Block{initialBlock},
		difficulty: difficulty,
	}
}

func (bc *Blockchain) getLatestBlock() *Block {
	return bc.blocks[len(bc.blocks)-1]
}

func (bc *Blockchain) addBlock(data string) {
	lastBlock := bc.getLatestBlock()

	newBlock := generateBlock(lastBlock, data)
	newBlock.mineBlock(bc.difficulty)
	bc.blocks = append(bc.blocks, newBlock)
}

func (bc *Blockchain) isChainValid() bool {
	target := strings.Repeat("0", bc.difficulty)

	for i := 1; i < len(bc.blocks); i++ {
		currentBlock := bc.blocks[i]
		previousBlock := bc.blocks[i-1]

		if currentBlock.Hash != currentBlock.calculateHash() {
			fmt.Println("Current block's hash is invalid")
			return false
		}

		if currentBlock.PreviousHash != previousBlock.Hash {
			fmt.Println("Previous block's hash does not match")
			return false
		}

		if !strings.HasPrefix(currentBlock.Hash, target) {
			fmt.Println("Current block's hash does not meet the difficulty requirement")
			return false
		}
	}

	return true
}

func (bc *Blockchain) displayBlockchain() {
	fmt.Println("\n" + strings.Repeat("=", 50))
	fmt.Println("BLOCKCHAIN (Difficulty:", bc.difficulty, ")")
	fmt.Println(strings.Repeat("=", 50))

	for _, block := range bc.blocks {
		fmt.Printf("\nBlock %d:\n", block.Index)
		fmt.Printf("  Timestamp: %s\n", time.Unix(block.Timestamp, 0).Format("2006-01-02 15:04:05"))
		fmt.Printf("  Data: %s\n", block.Data)
		fmt.Printf("  Previous Hash: %s\n", block.PreviousHash)
		fmt.Printf("  Nonce: %d\n", block.Nonce)
		fmt.Printf("  Hash: %s\n", block.Hash)
		fmt.Printf("  Proof of Work: %s✓\n", strings.Repeat("0", bc.difficulty))
	}
}

func (bc *Blockchain) demonstrateTampering() {
	fmt.Println("\n" + strings.Repeat("=", 50))
	fmt.Println("TAMPERING DEMONSTRATION")
	fmt.Println(strings.Repeat("=", 50))

	// Try to tamper with block 1
	if len(bc.blocks) > 1 {
		fmt.Println("Original blockchain is valid:", bc.isChainValid())

		// Tamper with data
		originalData := bc.blocks[1].Data
		bc.blocks[1].Data = "HACKED: Alice sends 1000 coins to Eve"

		fmt.Println("After tampering with block 1...")
		fmt.Println("Blockchain is valid:", bc.isChainValid())

		// Restore original data
		bc.blocks[1].Data = originalData
		fmt.Println("After restoring original data...")
		fmt.Println("Blockchain is valid:", bc.isChainValid())
	}
}

func main() {
	fmt.Println("🚀 Starting Blockchain with Proof of Work Mining")
	fmt.Println("Difficulty: 4 (hash must start with 0000)")
	bc := NewBlockchain(4)

	fmt.Println("\n📦 Adding blocks to blockchain...")
	bc.addBlock("Alice sends 10 coins to Bob")
	bc.addBlock("Bob sends 5 coins to Charlie")
	bc.addBlock("Charlie sends 3 coins to Dave\n\n")

	bc.displayBlockchain()

	fmt.Println("\n🔍 Blockchain validation:", bc.isChainValid())

	bc.demonstrateTampering()

	fmt.Println("\n✨ Mining complete! Notice how each hash starts with 0000")
	fmt.Println("💡 Try changing the difficulty to see how it affects mining time!")
}
