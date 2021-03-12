storage.true = storage.Bool;
storage.false = storage.Bool;

storage.walletEntry publicKey:string secret:bytes = storage.WalletEntry; // old
storage.walletEntryGeneric publicKey:string secret:bytes address:string = storage.WalletEntry;
storage.walletEntryFtabi name:string publicKey:string secret:bytes = storage.WalletEntry;
storage.walletList entries:vector<storage.WalletEntry> = storage.WalletList;
storage.transactionId lt:int64 hash:bytes = storage.TransactionId;
storage.restrictionLimit seconds:int32 lockedAmount:int64 = storage.RestrictionLimit;
storage.accountStateNormal = storage.AccountStateDetails;
storage.accountStateRestricted lockedBalance:int64 startAt:int64 limits:vector<storage.RestrictionLimit> = storage.AccountStateDetails;
storage.accountState balance:int64 syncTime:int64 lastTransactionId:storage.TransactionId = storage.AccountState; // old
storage.accountStateFull balance:int64 syncTime:int64 lastTransactionId:storage.TransactionId details:storage.AccountStateDetails = storage.AccountState;
storage.messageDataTextEncrypted data:bytes = storage.MessageData;
storage.messageDataTextDecrypted text:string = storage.MessageData;
storage.messageDataTextPlain text:string = storage.MessageData;
storage.messageDataRaw body:bytes = storage.MessageData;

storage.additionalInfoRegular = storage.TransactionAdditionalInfo;

storage.tokenWalletDeployed rootTokenContract:string = storage.TransactionAdditionalInfo;
storage.tokenEthEventStatusChanged status:int32 = storage.TransactionAdditionalInfo;
storage.tokenTonEventStatusChanged status:int32 = storage.TransactionAdditionalInfo;
storage.tokenTransfer address:string value:bytes incoming:storage.Bool direct:storage.Bool = storage.TransactionAdditionalInfo;
storage.tokenSwapBack address:string value:bytes = storage.TransactionAdditionalInfo;
storage.tokenMint value:bytes = storage.TransactionAdditionalInfo;
storage.tokenBounced value:bytes = storage.TransactionAdditionalInfo;

storage.dePoolOrdinaryStake stake:int64 = storage.TransactionAdditionalInfo;
storage.dePoolOnRoundComplete
    roundId:int64
    reward:int64
    ordinaryStake:int64
    vestingStake:int64
    lockStake:int64
    reinvest:storage.Bool
    reason:int32 = storage.TransactionAdditionalInfo;

storage.message
    source:string
    destination:string
    value:int64
    created:int64
    bodyHash:bytes
    message:storage.MessageData
    bounce:storage.Bool
    bounced:storage.Bool = storage.Message;
storage.transaction
    id:storage.TransactionId
    time:int64
    fee:int64
    storageFee:int64
    otherFee:int64
    incoming:storage.Message
    outgoing:vector<storage.Message>
    aborted:storage.Bool
    additional:storage.TransactionAdditionalInfo = storage.Transaction;
storage.transactionsSlice list:vector<storage.Transaction> previousId:storage.TransactionId = storage.TransactionsSlice;
storage.pendingTransaction fake:storage.Transaction sentUntilSyncTime:int64 = storage.PendingTransaction;
storage.tokenState
    rootContractAddress:bytes
    walletContractAddress:bytes
    rootOwnerAddress:bytes
    name:bytes
    decimals:int32
    lastTransactions:storage.TransactionsSlice
    balance:bytes = storage.TokenState;
storage.dePoolState
    address:string
    version:int32
    total:int64
    withdrawValue:int64
    reinvest:storage.Bool
    reward:int64 = storage.DePoolState;
storage.multisigState
    address:string
    version:int32
    publicKey:bytes
    state:storage.AccountState
    lastTransactions:storage.TransactionsSlice
    pendingTransactions:vector<storage.PendingTransaction>
    custodians:vector<bytes>
    expirationTime:int64 = storage.MultisigState;
storage.assetsListMain = storage.AssetsListItem;
storage.assetsListToken name:bytes decimals:int32 rootContractAddress:bytes = storage.AssetsListItem;
storage.assetsListDePool address:string = storage.AssetsListItem;
storage.assetsListMultisig address:string = storage.AssetsListItem;
storage.walletState
    address:string
    account:storage.AccountState
    lastTransactions:storage.TransactionsSlice
    pendingTransactions:vector<storage.PendingTransaction>
    tokenStates:vector<storage.TokenState>
    dePoolStates:vector<storage.DePoolState>
    multisigStates:vector<storage.MultisigState>
    assetsList:vector<storage.AssetsListItem> = storage.WalletState;

storage.tokenOwnersCacheItem wallet:bytes owner:bytes = storage.TokenOwnersCacheItem;
storage.tokenOwnersCache wallets:vector<storage.tokenOwnersCacheItem> = storage.TokenOwnersCache;
storage.knownTokenContracts addresses:vector<string> = storage.KnownTokenContracts;

storage.network blockchainName:string configUrl:string config:string useCustomConfig:storage.Bool = storage.Network;
storage.settings blockchainName:string configUrl:string config:string useCustomConfig:storage.Bool useNetworkCallbacks:storage.Bool = storage.Settings; // old
storage.settings2 blockchainName:string configUrl:string config:string useCustomConfig:storage.Bool useNetworkCallbacks:storage.Bool version:int32 = storage.Settings; // old
storage.settings3 main:storage.Network test:storage.Network useTestNetwork:storage.Bool useNetworkCallbacks:storage.Bool version:int32 = storage.Settings;
