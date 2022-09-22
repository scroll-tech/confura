package rpc

import (
	"context"
	"math/big"

	"github.com/pkg/errors"
	"github.com/scroll-tech/go-ethereum/core/types"
	"github.com/scroll-tech/go-ethereum/rpc"
)

// scrollAPI provides an RPC proxy for Scroll-specific APIs.
type scrollAPI struct{}

func (api *scrollAPI) GetBlockResultByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*types.BlockResult, error) {
	client := GetScrollClientFromContext(ctx)

	if number, ok := blockNrOrHash.Number(); ok {
		return client.GetBlockResultByNumber(ctx, new(big.Int).SetInt64(number.Int64()))
	}

	if hash, ok := blockNrOrHash.Hash(); ok {
		return client.GetBlockResultByHash(ctx, hash)
	}

	return nil, errors.New("scroll_getBlockResultByNumberOrHash parameter neither number nor hash")
}
