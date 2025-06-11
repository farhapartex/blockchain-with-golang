package main

import (
	"crypto/sha256"
	"fmt"
	"strconv"
	"time"
)

type Block struct {
	Index        int
	Timestamp    int64
	Data         string
	PreviousHash string
	Hash         string
}

func (b *Block) calculateHash() string {
	record := strconv.Itoa(b.Index) + strconv.FormatInt(b.Timestamp, 10) + b.Data + b.PreviousHash

	h := sha256.New()
	h.Write([]byte(record))
	hashed := h.Sum(nil)

	return fmt.Sprintf("%x", hashed)
}

func generateGenesisBlock() *Block {
	block := Block{
		Index:        0,
		Timestamp:    time.Now().Unix(),
		Data:         "Genesis Block",
		PreviousHash: "",
		Hash:         "",
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

func isBlockValid(newBlock *Block, oldBlock *Block) bool {
	if oldBlock.Index+1 != newBlock.Index {
		return false
	}
	if oldBlock.Hash != newBlock.PreviousHash {
		return false
	}
	if newBlock.Hash != newBlock.calculateHash() {
		return false
	}
	return true
}

func main() {
	blockChain := []*Block{}
	initialBlock := generateGenesisBlock()

	initialBlock.Hash = initialBlock.calculateHash()

	blockChain = append(blockChain, initialBlock)

	//  Add few blocks to the blockchain
	block1 := generateBlock(blockChain[0], "Transaction: Alice pays Bob 10 BTC")

	if isBlockValid(block1, blockChain[0]) {
		blockChain = append(blockChain, block1)
		fmt.Println("Block 1 added to the blockchain")
	} else {
		fmt.Println("Block 1 is invalid")
	}

	block2 := generateBlock(blockChain[1], "Transaction: Bob pays Charlie 5 BTC")
	if isBlockValid(block2, blockChain[1]) {
		blockChain = append(blockChain, block2)
		fmt.Println("Block 1 added to the blockchain")
	} else {
		fmt.Println("Block 1 is invalid")
	}

	for i, block := range blockChain {
		fmt.Printf("Block %d:\n", i)
		fmt.Printf("Index: %d\n", block.Index)
		fmt.Printf("Timestamp: %d\n", block.Timestamp)
		fmt.Printf("Data: %s\n", block.Data)
		fmt.Printf("Previous Hash: %s\n", block.PreviousHash)
		fmt.Printf("Hash: %s\n", block.Hash)
		fmt.Println()
	}
}
