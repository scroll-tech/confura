package cmd

import (
	sdk "github.com/Conflux-Chain/go-conflux-sdk"
	"github.com/conflux-chain/conflux-infura/store"
	"github.com/conflux-chain/conflux-infura/store/mysql"
	"github.com/conflux-chain/conflux-infura/store/redis"
	"github.com/conflux-chain/conflux-infura/util"
	"github.com/openweb3/web3go"
	"github.com/spf13/viper"
)

type storeContext struct {
	cfxDB    store.Store
	ethDB    store.Store
	cfxCache store.CacheStore
}

func mustInitStoreContext(calibrateEpochStats bool) storeContext {
	var ctx storeContext

	if config := mysql.MustNewConfigFromViper(); config.Enabled {
		ctx.cfxDB = config.MustOpenOrCreate(mysql.StoreOption{CalibrateEpochStats: calibrateEpochStats})
	}

	if ethConfig := mysql.MustNewEthStoreConfigFromViper(); ethConfig.Enabled {
		ctx.ethDB = ethConfig.MustOpenOrCreate(mysql.StoreOption{CalibrateEpochStats: calibrateEpochStats})
	}

	if cache, ok := redis.MustNewCacheStoreFromViper(); ok {
		ctx.cfxCache = cache
	}

	return ctx
}

func (ctx *storeContext) Close() {
	if ctx.cfxDB != nil {
		ctx.cfxDB.Close()
	}

	if ctx.ethDB != nil {
		ctx.ethDB.Close()
	}

	if ctx.cfxCache != nil {
		ctx.cfxCache.Close()
	}
}

type syncContext struct {
	storeContext
	syncCfx *sdk.Client
	subCfx  *sdk.Client
	syncEth *web3go.Client
}

func mustInitSyncContext(storeCtx storeContext) syncContext {
	return syncContext{
		storeContext: storeCtx,
		syncCfx:      util.MustNewCfxClient(viper.GetString("cfx.http")),
		subCfx:       util.MustNewCfxClient(viper.GetString("cfx.ws")),
		syncEth:      util.MustNewEthClientFromViper(),
	}
}

func (ctx *syncContext) Close() {
	// Usually, storeContext will be defer closed by itself
	// ctx.storeContext.Close()
	ctx.syncCfx.Close()
	ctx.subCfx.Close()
	// not provided yet!
	// ctx.syncEth.Close()
}