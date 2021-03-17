// This file is part of Desktop App Toolkit,
// a set of libraries for developing nice desktop applications.
//
// For license and copyright information please follow this link:
// https://github.com/desktop-app/legal/blob/master/LEGAL
//
#include "ton/details/ton_storage.h"

#include "ton/details/ton_request_sender.h"
#include "ton/ton_state.h"
#include "ton/ton_settings.h"
#include "storage/cache/storage_cache_database.h"
#include "ton_storage_tl.h"

namespace Ton::details {
namespace {

constexpr auto kSettingsKey = Storage::Cache::Key{1ULL, 0ULL};
constexpr auto kWalletTestListKey = Storage::Cache::Key{1ULL, 1ULL};
constexpr auto kWalletMainListKey = Storage::Cache::Key{1ULL, 2ULL};
constexpr auto kKnownTokenContractsTestList = Storage::Cache::Key{1ULL, 3ULL};
constexpr auto kKnownTokenContractsMainList = Storage::Cache::Key{1ULL, 4ULL};
constexpr auto kIgnoredAssetsTestList = Storage::Cache::Key{1ULL, 5ULL};
constexpr auto kIgnoredAssetsMainList = Storage::Cache::Key{1ULL, 6ULL};

[[nodiscard]] Storage::Cache::Key WalletListKey(bool useTestNetwork) {
  return useTestNetwork ? kWalletTestListKey : kWalletMainListKey;
}

[[nodiscard]] Storage::Cache::Key IgnoredAssetsListKey(bool useTestNetwork) {
  return useTestNetwork ? kIgnoredAssetsTestList : kIgnoredAssetsMainList;
}

[[nodiscard]] Storage::Cache::Key WalletStateKey(const QString &address) {
  const auto utf8 = address.toUtf8();
  const auto decoded = QByteArray::fromBase64(address.toUtf8(), QByteArray::Base64UrlEncoding);
  Assert(decoded.size() == 36);
  auto a = uint64();
  auto b = uint64();
  memcpy(&a, decoded.data() + 2, sizeof(uint64));
  memcpy(&b, decoded.data() + 2 + sizeof(uint64), sizeof(uint64));
  return {0x2ULL | (a & 0xFFFFFFFFFFFF0000ULL), b};
}

[[nodiscard]] Storage::Cache::Key TokenOwnersCacheKey(bool useTestNetwork, const QString &rootContractAddress) {
  return {useTestNetwork ? 0x3ULL : 0x4ULL, qHash(rootContractAddress)};
}

[[nodiscard]] Storage::Cache::Key KnownTokenContractsKey(bool useTestNetwork) {
  return useTestNetwork ? kKnownTokenContractsTestList : kKnownTokenContractsMainList;
}

[[nodiscard]] QString ConvertLegacyUrl(const QString &configUrl) {
  return (configUrl == "https://test.ton.org/config.json") ? "https://ton.org/config-test.json" : configUrl;
}

[[nodiscard]] QString ConvertLegacyTestBlockchainName(const QString &name) {
  return (name == "mainnet") ? "mainnet-test" : name;
}

struct NamedDePoolState {
  QString address;
  DePoolParticipantState state;
};

struct NamedMultisigState {
  QString address;
  MultisigState state;
};

using WalletListEntry = std::variant<WalletList::Entry, WalletList::FtabiEntry>;

TLstorage_Bool Serialize(const bool &data);
bool Deserialize(const TLstorage_Bool &data);
TLstorage_WalletEntry Serialize(const WalletList::Entry &data);
TLstorage_WalletEntry Serialize(const WalletList::FtabiEntry &data);
WalletListEntry Deserialize(const TLstorage_WalletEntry &data);
TLstorage_WalletList Serialize(const WalletList &data);
WalletList Deserialize(const TLstorage_WalletList &data);
TLstorage_TransactionId Serialize(const TransactionId &data);
TransactionId Deserialize(const TLstorage_TransactionId &data);
TLstorage_RestrictionLimit Serialize(const RestrictionLimit &data);
RestrictionLimit Deserialize(const TLstorage_RestrictionLimit &data);
TLstorage_AccountState Serialize(const AccountState &data);
AccountState Deserialize(const TLstorage_AccountState &data);
TLstorage_Message Serialize(const Message &data);
Message Deserialize(const TLstorage_Message &data);
TLstorage_TransactionAdditionalInfo Serialize(const TransactionAdditionalInfo &data);
TransactionAdditionalInfo Deserialize(const TLstorage_TransactionAdditionalInfo &data);
TLstorage_Transaction Serialize(const Transaction &data);
Transaction Deserialize(const TLstorage_Transaction &data);
TLstorage_TransactionsSlice Serialize(const TransactionsSlice &data);
TransactionsSlice Deserialize(const TLstorage_TransactionsSlice &data);
TLstorage_PendingTransaction Serialize(const PendingTransaction &data);
PendingTransaction Deserialize(const TLstorage_PendingTransaction &data);
TLstorage_TokenState Serialize(const TokenState &data);
TokenState Deserialize(const TLstorage_TokenState &data);
TLstorage_DePoolState Serialize(const NamedDePoolState &data);
NamedDePoolState Deserialize(const TLstorage_DePoolState &data);
TLstorage_MultisigState Serialize(const NamedMultisigState &data);
NamedMultisigState Deserialize(const TLstorage_MultisigState &data);
TLstorage_AssetsListItem Serialize(const AssetListItem &data);
AssetListItem Deserialize(const TLstorage_AssetsListItem &data);
TLstorage_WalletState Serialize(const WalletState &data);
WalletState Deserialize(const TLstorage_WalletState &data);
TLstorage_IgnoredAssetsListItem Serialize(const IgnoredAssetListItem &data);
IgnoredAssetListItem Deserialize(const TLstorage_IgnoredAssetsListItem &data);
TLstorage_TokenOwnersCache Serialize(const TokenOwnersCache &data);
TokenOwnersCache Deserialize(const TLstorage_TokenOwnersCache &data);
TLstorage_KnownTokenContracts Serialize(const KnownTokenContracts &data);
KnownTokenContracts Deserialize(const TLstorage_KnownTokenContracts &data);
TLstorage_Settings Serialize(const Settings &data);
Settings Deserialize(const TLstorage_Settings &data);

template <typename Data, typename Result = decltype(Serialize(std::declval<Data>()))>
TLvector<Result> Serialize(const std::vector<Data> &data) {
  auto result = QVector<Result>();
  result.reserve(data.size());
  for (const auto &entry : data) {
    result.push_back(Serialize(entry));
  }
  return tl_vector<Result>(std::move(result));
}

template <typename TLType, typename Result = decltype(Deserialize(std::declval<TLType>()))>
std::vector<Result> Deserialize(const TLvector<TLType> &data) {
  auto result = std::vector<Result>();
  result.reserve(data.v.size());
  for (const auto &entry : data.v) {
    result.emplace_back(Deserialize(entry));
  }
  return result;
}

TLstorage_Bool Serialize(const bool &data) {
  return data ? make_storage_true() : make_storage_false();
}

bool Deserialize(const TLstorage_Bool &data) {
  return data.match([&](const TLDstorage_true &data) { return true; },
                    [&](const TLDstorage_false &data) { return false; });
}

TLstorage_WalletEntry Serialize(const WalletList::Entry &data) {
  return make_storage_walletEntryGeneric(tl_string(data.publicKey), tl_bytes(data.secret), tl_string(data.address));
}

TLstorage_WalletEntry Serialize(const WalletList::FtabiEntry &data) {
  return make_storage_walletEntryFtabi(tl_string(data.name), tl_string(data.publicKey), tl_bytes(data.secret));
}

WalletListEntry Deserialize(const TLstorage_WalletEntry &data) {
  return data.match(
      [&](const TLDstorage_walletEntry &data) -> WalletListEntry {
        return WalletList::Entry{
            .publicKey = data.vpublicKey().v,
            .secret = data.vsecret().v,
        };
      },
      [&](const TLDstorage_walletEntryGeneric &data) -> WalletListEntry {
        return WalletList::Entry{
            .publicKey = data.vpublicKey().v,
            .secret = data.vsecret().v,
            .address = tl::utf16(data.vaddress()),
        };
      },
      [&](const TLDstorage_walletEntryFtabi &data) -> WalletListEntry {
        return WalletList::FtabiEntry{
            .name = data.vname().v,
            .publicKey = data.vpublicKey().v,
            .secret = data.vsecret().v,
        };
      });
}

TLstorage_WalletList Serialize(const WalletList &data) {
  TLVector<TLstorage_WalletEntry> entries;
  entries.v.reserve(data.entries.size() + data.ftabiEntries.size());
  for (const auto &entry : data.entries) {
    entries.v.push_back(Serialize(entry));
  }
  for (const auto &ftabiEntry : data.ftabiEntries) {
    entries.v.push_back(Serialize(ftabiEntry));
  }
  return make_storage_walletList(entries);
}

WalletList Deserialize(const TLstorage_WalletList &data) {
  auto result = WalletList();
  data.match([&](const TLDstorage_walletList &data) {
    auto entries = Deserialize(data.ventries());
    for (auto &entry : entries) {
      v::match(
          entry, [&](WalletList::Entry &entry) { result.entries.emplace_back(std::move(entry)); },
          [&](WalletList::FtabiEntry &entry) { result.ftabiEntries.emplace_back(std::move(entry)); });
    }
  });
  return result;
}

TLstorage_TransactionId Serialize(const TransactionId &data) {
  return make_storage_transactionId(tl_int64(data.lt), tl_bytes(data.hash));
}

TransactionId Deserialize(const TLstorage_TransactionId &data) {
  return data.match([&](const TLDstorage_transactionId &data) { return TransactionId{data.vlt().v, data.vhash().v}; });
}

TLstorage_RestrictionLimit Serialize(const RestrictionLimit &data) {
  return make_storage_restrictionLimit(tl_int32(data.seconds), tl_int64(data.lockedAmount));
}

RestrictionLimit Deserialize(const TLstorage_RestrictionLimit &data) {
  return data.match([&](const TLDstorage_restrictionLimit &data) {
    return RestrictionLimit{.seconds = data.vseconds().v, .lockedAmount = data.vlockedAmount().v};
  });
}

TLstorage_AccountState Serialize(const AccountState &data) {
  const auto restricted = data.lockedBalance || data.restrictionStartAt || !data.restrictionLimits.empty();
  return make_storage_accountStateFull(
      tl_int64(data.fullBalance), tl_int64(data.syncTime), Serialize(data.lastTransactionId),
      (restricted ? make_storage_accountStateRestricted(tl_int64(data.lockedBalance), tl_int64(data.restrictionStartAt),
                                                        Serialize(data.restrictionLimits))
                  : make_storage_accountStateNormal()));
}

AccountState Deserialize(const TLstorage_AccountState &data) {
  return data.match(
      [&](const TLDstorage_accountState &data) {
        return AccountState{.fullBalance = data.vbalance().v,
                            .syncTime = data.vsyncTime().v,
                            .lastTransactionId = Deserialize(data.vlastTransactionId())};
      },
      [&](const TLDstorage_accountStateFull &data) {
        auto result = AccountState{.fullBalance = data.vbalance().v,
                                   .syncTime = data.vsyncTime().v,
                                   .lastTransactionId = Deserialize(data.vlastTransactionId())};
        data.vdetails().match([&](const TLDstorage_accountStateNormal &) {},
                              [&](const TLDstorage_accountStateRestricted &data) {
                                result.restrictionStartAt = data.vstartAt().v;
                                result.lockedBalance = data.vlockedBalance().v;
                                result.restrictionLimits = Deserialize(data.vlimits());
                              });
        return result;
      });
}

TLstorage_MessageData Serialize(const MessageData &data) {
  switch (data.type) {
    case MessageDataType::PlainText:
      return make_storage_messageDataTextPlain(tl_string(data.text));
    case MessageDataType::EncryptedText:
      return make_storage_messageDataTextEncrypted(tl_bytes(data.data));
    case MessageDataType::DecryptedText:
      return make_storage_messageDataTextDecrypted(tl_string(data.text));
    case MessageDataType::RawBody:
      return make_storage_messageDataRaw(tl_bytes(data.data));
    default:
      Assert(false);
  }
}

MessageData Deserialize(const TLstorage_MessageData &data) {
  return data.match(
      [&](const TLDstorage_messageDataTextEncrypted &data) {
        return MessageData{.text = {}, .data = tl::utf8(data.vdata()), .type = MessageDataType::EncryptedText};
      },
      [&](const TLDstorage_messageDataTextDecrypted &data) {
        return MessageData{.text = tl::utf16(data.vtext()), .data = {}, .type = MessageDataType::DecryptedText};
      },
      [&](const TLDstorage_messageDataTextPlain &data) {
        return MessageData{.text = tl::utf16(data.vtext()), .data = {}, .type = MessageDataType::PlainText};
      },
      [&](const TLDstorage_messageDataRaw &data) {
        return MessageData{.text = {}, .data = data.vbody().v, .type = MessageDataType::RawBody};
      });
}

TLstorage_Message Serialize(const Message &data) {
  return make_storage_message(tl_string(data.source), tl_string(data.destination), tl_int64(data.value),
                              tl_int64(data.created), tl_bytes(data.bodyHash), Serialize(data.message),
                              Serialize(data.bounce), Serialize(data.bounced));
}

Message Deserialize(const TLstorage_Message &data) {
  return data.match([&](const TLDstorage_message &data) {
    return Message{.source = tl::utf16(data.vsource()),
                   .destination = tl::utf16(data.vdestination()),
                   .value = data.vvalue().v,
                   .created = data.vcreated().v,
                   .bodyHash = data.vbodyHash().v,
                   .message = Deserialize(data.vmessage()),
                   .bounce = Deserialize(data.vbounce()),
                   .bounced = Deserialize(data.vbounced())};
  });
}

TLstorage_TransactionAdditionalInfo Serialize(const TransactionAdditionalInfo &data) {
  return v::match(
      data,
      [](const RegularTransaction &) -> TLstorage_TransactionAdditionalInfo {
        return make_storage_additionalInfoRegular();
      },
      [](const TokenWalletDeployed &data) -> TLstorage_TransactionAdditionalInfo {
        return make_storage_tokenWalletDeployed(tl_string(data.rootTokenContract));
      },
      [](const EthEventStatusChanged &data) -> TLstorage_TransactionAdditionalInfo {
        return make_storage_tokenEthEventStatusChanged(tl_int32(static_cast<int32>(data.status)));
      },
      [](const TonEventStatusChanged &data) -> TLstorage_TransactionAdditionalInfo {
        return make_storage_tokenTonEventStatusChanged(tl_int32(static_cast<int32>(data.status)));
      },
      [](const TokenTransfer &data) -> TLstorage_TransactionAdditionalInfo {
        return make_storage_tokenTransfer(tl_string(data.address), tl_bytes(Int128ToBytesBE(data.value)),
                                          Serialize(data.incoming), Serialize(data.direct));
      },
      [](const TokenSwapBack &data) -> TLstorage_TransactionAdditionalInfo {
        return make_storage_tokenSwapBack(tl_string(data.address), tl_bytes(Int128ToBytesBE(data.value)));
      },
      [](const TokenMint &data) -> TLstorage_TransactionAdditionalInfo {
        return make_storage_tokenMint(tl_bytes(Int128ToBytesBE(data.value)));
      },
      [](const TokensBounced &data) -> TLstorage_TransactionAdditionalInfo {
        return make_storage_tokenBounced(tl_bytes(Int128ToBytesBE(data.amount)));
      },
      [](const DePoolOrdinaryStakeTransaction &data) -> TLstorage_TransactionAdditionalInfo {
        return make_storage_dePoolOrdinaryStake(tl_int64(data.stake));
      },
      [](const DePoolOnRoundCompleteTransaction &data) -> TLstorage_TransactionAdditionalInfo {
        return make_storage_dePoolOnRoundComplete(
            tl_int64(data.roundId), tl_int64(data.reward), tl_int64(data.ordinaryStake), tl_int64(data.vestingStake),
            tl_int64(data.lockStake), Serialize(data.reinvest), tl_int32(data.reason));
      },
      [](const MultisigDeploymentTransaction &data) -> TLstorage_TransactionAdditionalInfo {
        return make_storage_multisigDeploymentTransaction();
      },
      [](const MultisigSubmitTransaction &data) -> TLstorage_TransactionAdditionalInfo {
        return make_storage_multisigSubmitTransaction(tl_string(data.dest), tl_int64(data.amount),
                                                      tl_int64(data.transactionId), Serialize(data.bounce),
                                                      Serialize(data.executed), tl_string(data.comment));
      },
      [](const MultisigConfirmTransaction &data) -> TLstorage_TransactionAdditionalInfo {
        return make_storage_multisigConfirmTransaction(tl_int64(data.transactionId), Serialize(data.executed));
      });
}

TransactionAdditionalInfo Deserialize(const TLstorage_TransactionAdditionalInfo &data) {
  return data.match(
      [](const TLDstorage_additionalInfoRegular &) -> TransactionAdditionalInfo { return RegularTransaction{}; },
      [](const TLDstorage_tokenWalletDeployed &data) -> TransactionAdditionalInfo {
        return TokenWalletDeployed{
            .rootTokenContract = tl::utf8(data.vrootTokenContract().v),
        };
      },
      [](const TLDstorage_tokenEthEventStatusChanged &data) -> TransactionAdditionalInfo {
        return EthEventStatusChanged{.status = static_cast<EthEventStatus>(data.vstatus().v)};
      },
      [](const TLDstorage_tokenTonEventStatusChanged &data) -> TransactionAdditionalInfo {
        return TonEventStatusChanged{.status = static_cast<TonEventStatus>(data.vstatus().v)};
      },
      [](const TLDstorage_tokenTransfer &data) -> TransactionAdditionalInfo {
        return TokenTransfer{
            .address = data.vaddress().v,
            .value = BytesBEToInt128(data.vvalue().v),
            .incoming = Deserialize(data.vincoming()),
            .direct = Deserialize(data.vdirect()),
        };
      },
      [](const TLDstorage_tokenSwapBack &data) -> TransactionAdditionalInfo {
        return TokenSwapBack{
            .address = data.vaddress().v,
            .value = BytesBEToInt128(data.vvalue().v),
        };
      },
      [](const TLDstorage_tokenMint &data) -> TransactionAdditionalInfo {
        return TokenMint{
            .value = BytesBEToInt128(data.vvalue().v),
        };
      },
      [](const TLDstorage_tokenBounced &data) -> TransactionAdditionalInfo {
        return TokensBounced{
            .amount = BytesBEToInt128(data.vvalue().v),
        };
      },
      [](const TLDstorage_dePoolOrdinaryStake &data) -> TransactionAdditionalInfo {
        return DePoolOrdinaryStakeTransaction{.stake = data.vstake().v};
      },
      [](const TLDstorage_dePoolOnRoundComplete &data) -> TransactionAdditionalInfo {
        return DePoolOnRoundCompleteTransaction{
            .roundId = data.vroundId().v,
            .reward = data.vreward().v,
            .ordinaryStake = data.vordinaryStake().v,
            .vestingStake = data.vvestingStake().v,
            .lockStake = data.vlockStake().v,
            .reinvest = Deserialize(data.vreinvest()),
            .reason = static_cast<uint8>(data.vreason().v),
        };
      },
      [](const TLDstorage_multisigDeploymentTransaction &data) -> TransactionAdditionalInfo {
        return MultisigDeploymentTransaction{};
      },
      [](const TLDstorage_multisigSubmitTransaction &data) -> TransactionAdditionalInfo {
        return MultisigSubmitTransaction{
            .dest = data.vdest().v,
            .amount = data.vamount().v,
            .transactionId = data.vtransactionId().v,
            .bounce = Deserialize(data.vbounce()),
            .executed = Deserialize(data.vexecuted()),
            .comment = data.vcomment().v,
        };
      },
      [](const TLDstorage_multisigConfirmTransaction &data) -> TransactionAdditionalInfo {
        return MultisigConfirmTransaction{
            .transactionId = data.vtransactionId().v,
            .executed = Deserialize(data.vexecuted()),
        };
      });
}

TLstorage_Transaction Serialize(const Transaction &data) {
  return make_storage_transaction(Serialize(data.id), tl_int64(data.time), tl_int64(data.fee),
                                  tl_int64(data.storageFee), tl_int64(data.otherFee), Serialize(data.incoming),
                                  Serialize(data.outgoing), Serialize(data.aborted), Serialize(data.additional));
}

Transaction Deserialize(const TLstorage_Transaction &data) {
  return data.match([&](const TLDstorage_transaction &data) {
    return Transaction{.id = Deserialize(data.vid()),
                       .time = data.vtime().v,
                       .fee = data.vfee().v,
                       .storageFee = data.vstorageFee().v,
                       .otherFee = data.votherFee().v,
                       .incoming = Deserialize(data.vincoming()),
                       .outgoing = Deserialize(data.voutgoing()),
                       .aborted = Deserialize(data.vaborted()),
                       .additional = Deserialize(data.vadditional())};
  });
}

TLstorage_TransactionsSlice Serialize(const TransactionsSlice &data) {
  return make_storage_transactionsSlice(Serialize(data.list), Serialize(data.previousId));
}

TransactionsSlice Deserialize(const TLstorage_TransactionsSlice &data) {
  return data.match([&](const TLDstorage_transactionsSlice &data) {
    return TransactionsSlice{Deserialize(data.vlist()), Deserialize(data.vpreviousId())};
  });
}

TLstorage_PendingTransaction Serialize(const PendingTransaction &data) {
  return make_storage_pendingTransaction(Serialize(data.fake), tl_int64(data.sentUntilSyncTime));
}

PendingTransaction Deserialize(const TLstorage_PendingTransaction &data) {
  return data.match([&](const TLDstorage_pendingTransaction &data) {
    return PendingTransaction{Deserialize(data.vfake()), data.vsentUntilSyncTime().v};
  });
}

TLstorage_TokenState Serialize(const TokenState &data) {
  Assert(data.token.isToken());
  return make_storage_tokenState2(tl_int32(static_cast<int32>(data.version)),
                                  tl_string(data.token.rootContractAddress()), tl_string(data.walletContractAddress),
                                  tl_string(data.rootOwnerAddress), tl_string(data.token.name()),
                                  tl_int32(static_cast<int32_t>(data.token.decimals())),
                                  Serialize(data.lastTransactions), tl_bytes(Int128ToBytesBE(data.balance)));
}

TokenState Deserialize(const TLstorage_TokenState &data) {
  return data.match(
      [&](const TLDstorage_tokenState &data) {
        return TokenState{.token = Symbol::tip3(tl::utf8(data.vname().v), static_cast<size_t>(data.vdecimals().v),
                                                data.vrootContractAddress().v),
                          .version = TokenVersion::tipo3v0,
                          .walletContractAddress = data.vwalletContractAddress().v,
                          .rootOwnerAddress = data.vrootOwnerAddress().v,
                          .lastTransactions = Deserialize(data.vlastTransactions()),
                          .balance = BytesBEToInt128(data.vbalance().v)};
      },
      [&](const TLDstorage_tokenState2 &data) {
        return TokenState{.token = Symbol::tip3(tl::utf8(data.vname().v), static_cast<size_t>(data.vdecimals().v),
                                                data.vrootContractAddress().v),
                          .version = static_cast<TokenVersion>(data.vversion().v),
                          .walletContractAddress = data.vwalletContractAddress().v,
                          .rootOwnerAddress = data.vrootOwnerAddress().v,
                          .lastTransactions = Deserialize(data.vlastTransactions()),
                          .balance = BytesBEToInt128(data.vbalance().v)};
      });
}

TLstorage_DePoolState Serialize(const NamedDePoolState &data) {
  return make_storage_dePoolState(tl_string(data.address), tl_int32(data.state.version), tl_int64(data.state.total),
                                  tl_int64(data.state.withdrawValue), Serialize(data.state.reinvest),
                                  tl_int64(data.state.reward));
}

NamedDePoolState Deserialize(const TLstorage_DePoolState &data) {
  return data.match([&](const TLDstorage_dePoolState &data) {
    auto address = QString::fromUtf8(data.vaddress().v);
    auto state = DePoolParticipantState{.version = data.vversion().v,
                                        .total = data.vtotal().v,
                                        .withdrawValue = data.vwithdrawValue().v,
                                        .reinvest = Deserialize(data.vreinvest()),
                                        .reward = data.vreward().v};
    return NamedDePoolState{std::move(address), state};
  });
}

TLstorage_MultisigState Serialize(const NamedMultisigState &data) {
  TLVector<TLstring> custodians;
  custodians.v.reserve(data.state.custodians.size());
  for (const auto &custodian : data.state.custodians) {
    custodians.v.push_back(tl_bytes(custodian));
  }

  return make_storage_multisigState(tl_string(data.address), tl_int32(static_cast<int32>(data.state.version)),
                                    tl_bytes(data.state.publicKey), Serialize(data.state.accountState),
                                    Serialize(data.state.lastTransactions), Serialize(data.state.pendingTransactions),
                                    custodians, tl_int64(data.state.expirationTime));
}

NamedMultisigState Deserialize(const TLstorage_MultisigState &data) {
  return data.match([&](const TLDstorage_multisigState &data) {
    auto address = QString::fromUtf8(data.vaddress().v);

    std::vector<QByteArray> custodians;
    custodians.reserve(data.vcustodians().v.size());
    for (const auto &custodian : data.vcustodians().v) {
      custodians.emplace_back(custodian.v);
    }

    auto state = MultisigState{
        .version = static_cast<Ton::MultisigVersion>(data.vversion().v),
        .publicKey = tl::utf8(data.vpublicKey().v),
        .accountState = Deserialize(data.vstate()),
        .lastTransactions = Deserialize(data.vlastTransactions()),
        .pendingTransactions = Deserialize(data.vpendingTransactions()),
        .custodians = std::move(custodians),
        .expirationTime = data.vexpirationTime().v,
    };
    return NamedMultisigState{.address = std::move(address), .state = std::move(state)};
  });
}

TLstorage_AssetsListItem Serialize(const AssetListItem &data) {
  return v::match(
      data, [](const AssetListItemWallet &) { return make_storage_assetsListMain(); },
      [](const AssetListItemToken &item) {
        return make_storage_assetsListToken(tl_string(item.symbol.name()), tl_int32(item.symbol.decimals()),
                                            tl_string(item.symbol.rootContractAddress()));
      },
      [](const AssetListItemDePool &item) { return make_storage_assetsListDePool(tl_string(item.address)); },
      [](const AssetListItemMultisig &item) { return make_storage_assetsListMultisig(tl_string(item.address)); });
}

AssetListItem Deserialize(const TLstorage_AssetsListItem &data) {
  return data.match([](const TLDstorage_assetsListMain &) -> AssetListItem { return AssetListItemWallet{}; },
                    [](const TLDstorage_assetsListToken &data) -> AssetListItem {
                      return AssetListItemToken{.symbol = Symbol::tip3(tl::utf8(data.vname().v), data.vdecimals().v,
                                                                       tl::utf8(data.vrootContractAddress().v))};
                    },
                    [](const TLDstorage_assetsListDePool &data) -> AssetListItem {
                      return AssetListItemDePool{.address = tl::utf8(data.vaddress().v)};
                    },
                    [](const TLDstorage_assetsListMultisig &data) -> AssetListItem {
                      return AssetListItemMultisig{.address = tl::utf8(data.vaddress().v)};
                    });
}

TLstorage_WalletState Serialize(const WalletState &data) {
  std::vector<TokenState> tokenStates;
  tokenStates.reserve(data.tokenStates.size());
  for (const auto &[symbol, state] : data.tokenStates) {
    tokenStates.emplace_back(state.withSymbol(symbol));
  }

  std::vector<NamedDePoolState> depoolStates;
  depoolStates.reserve(data.dePoolParticipantStates.size());
  for (const auto &[address, state] : data.dePoolParticipantStates) {
    depoolStates.emplace_back(NamedDePoolState{address, state});
  }

  std::vector<NamedMultisigState> multisigStates;
  multisigStates.reserve(data.multisigStates.size());
  for (const auto &[address, state] : data.multisigStates) {
    multisigStates.emplace_back(NamedMultisigState{address, state});
  }

  return make_storage_walletState(tl_string(data.address), Serialize(data.account), Serialize(data.lastTransactions),
                                  Serialize(data.pendingTransactions), Serialize(tokenStates), Serialize(depoolStates),
                                  Serialize(multisigStates), Serialize(data.assetsList));
}

WalletState Deserialize(const TLstorage_WalletState &data) {
  return data.match([&](const TLDstorage_walletState &data) {
    auto storedTokenStates = Deserialize(data.vtokenStates());
    CurrencyMap<TokenStateValue> tokenStates;
    for (auto &item : storedTokenStates) {
      tokenStates.insert({item.token, TokenStateValue{.walletContractAddress = item.walletContractAddress,
                                                      .rootOwnerAddress = item.rootOwnerAddress,
                                                      .lastTransactions = item.lastTransactions,
                                                      .balance = item.balance}});
    }

    auto storedDePoolStates = Deserialize(data.vdePoolStates());
    DePoolStatesMap depoolStates;
    for (auto &&[address, state] : storedDePoolStates) {
      depoolStates.emplace(std::piecewise_construct, std::forward_as_tuple(std::move(address)),
                           std::forward_as_tuple(std::move(state)));
    }

    auto storedMultisigStates = Deserialize(data.vmultisigStates());
    MultisigStatesMap multisigStates;
    for (auto &&[address, state] : storedMultisigStates) {
      multisigStates.emplace(std::piecewise_construct, std::forward_as_tuple(std::move(address)),
                             std::forward_as_tuple(std::move(state)));
    }

    auto assetsList = Deserialize(data.vassetsList());
    if (assetsList.empty()) {
      assetsList.emplace_back(AssetListItemWallet{});
    }

    return WalletState{.address = tl::utf16(data.vaddress()),
                       .account = Deserialize(data.vaccount()),
                       .lastTransactions = Deserialize(data.vlastTransactions()),
                       .pendingTransactions = Deserialize(data.vpendingTransactions()),
                       .tokenStates = std::move(tokenStates),
                       .dePoolParticipantStates = std::move(depoolStates),
                       .multisigStates = std::move(multisigStates),
                       .assetsList = std::move(assetsList)};
  });
}

TLstorage_IgnoredAssetsListItem Serialize(const IgnoredAssetListItem &data) {
  return v::match(
      data,
      [](const IgnoredAssetToken &data) {
        return make_storage_ignoredAssetsListToken(tl_bytes(data.rootTokensContractAddress.toUtf8()));
      },
      [](const IgnoredAssetDePool &data) {
        return make_storage_ignoredAssetsListDePool(tl_bytes(data.address.toUtf8()));
      });
}

IgnoredAssetListItem Deserialize(const TLstorage_IgnoredAssetsListItem &data) {
  return data.match(
      [](const TLDstorage_ignoredAssetsListToken &data) -> IgnoredAssetListItem {
        return IgnoredAssetToken{
            .rootTokensContractAddress = tl::utf8(data.vrootContractAddress().v),
        };
      },
      [](const TLDstorage_ignoredAssetsListDePool &data) -> IgnoredAssetListItem {
        return IgnoredAssetDePool{
            .address = tl::utf8(data.vaddress().v),
        };
      });
}

TLstorage_TokenOwnersCache Serialize(const TokenOwnersCache &data) {
  TLvector<TLstorage_tokenOwnersCacheItem> wallets;
  wallets.v.reserve(data.entries.size());
  for (const auto &[wallet, owner] : data.entries) {
    wallets.v.push_back(make_storage_tokenOwnersCacheItem(tl_string(wallet), tl_string(owner)));
  }
  return make_storage_tokenOwnersCache(wallets);
}

TokenOwnersCache Deserialize(const TLstorage_TokenOwnersCache &data) {
  TokenOwnersCache owners;
  for (const auto &item : data.c_storage_tokenOwnersCache().vwallets().v) {
    const auto &wallet = item.c_storage_tokenOwnersCacheItem();
    owners.entries.emplace(std::piecewise_construct, std::forward_as_tuple(wallet.vwallet().v),
                           std::forward_as_tuple(wallet.vowner().v));
  }
  return owners;
}

TLstorage_KnownTokenContracts Serialize(const KnownTokenContracts &data) {
  TLVector<TLstring> addresses;
  addresses.v.reserve(data.addresses.size());
  for (const auto &item : data.addresses) {
    addresses.v.push_back(tl_string(item));
  }
  return make_storage_knownTokenContracts(addresses);
}

KnownTokenContracts Deserialize(const TLstorage_KnownTokenContracts &data) {
  KnownTokenContracts result;
  const auto &addresses = data.c_storage_knownTokenContracts().vaddresses().v;
  result.addresses.reserve(addresses.size());
  for (const auto &item : addresses) {
    result.addresses.emplace_back(item.v);
  }
  return result;
}

TLstorage_Network Serialize(const NetSettings &data) {
  return make_storage_network(tl_string(data.blockchainName), tl_string(data.configUrl), tl_string(data.config),
                              Serialize(data.useCustomConfig));
}

NetSettings Deserialize(const TLstorage_Network &data) {
  return data.match([&](const TLDstorage_network &data) {
    return NetSettings{.blockchainName = tl::utf16(data.vblockchainName()),
                       .configUrl = tl::utf16(data.vconfigUrl()),
                       .config = tl::utf8(data.vconfig()),
                       .useCustomConfig = Deserialize(data.vuseCustomConfig())};
  });
}

TLstorage_Settings Serialize(const Settings &data) {
  return make_storage_settings3(Serialize(data.main), Serialize(data.test), Serialize(data.useTestNetwork),
                                Serialize(data.useNetworkCallbacks), tl_int32(data.version));
}

Settings Deserialize(const TLstorage_Settings &data) {
  return data.match(
      [&](const TLDstorage_settings &data) {
        return Settings{
            .test = NetSettings{.blockchainName = ConvertLegacyTestBlockchainName(tl::utf16(data.vblockchainName())),
                                .configUrl = ConvertLegacyUrl(tl::utf16(data.vconfigUrl())),
                                .config = tl::utf8(data.vconfig()),
                                .useCustomConfig = Deserialize(data.vuseCustomConfig())},
            .useTestNetwork = true,
            .useNetworkCallbacks = Deserialize(data.vuseNetworkCallbacks()),
            .version = 0};
      },
      [&](const TLDstorage_settings2 &data) {
        return Settings{
            .test = NetSettings{.blockchainName = ConvertLegacyTestBlockchainName(tl::utf16(data.vblockchainName())),
                                .configUrl = ConvertLegacyUrl(tl::utf16(data.vconfigUrl())),
                                .config = tl::utf8(data.vconfig()),
                                .useCustomConfig = Deserialize(data.vuseCustomConfig())},
            .useTestNetwork = true,
            .useNetworkCallbacks = Deserialize(data.vuseNetworkCallbacks()),
            .version = data.vversion().v};
      },
      [&](const TLDstorage_settings3 &data) {
        return Settings{
            .main = Deserialize(data.vmain()),
            .test = Deserialize(data.vtest()),
            .useTestNetwork = Deserialize(data.vuseTestNetwork()),
            .useNetworkCallbacks = Deserialize(data.vuseNetworkCallbacks()),
            .version = data.vversion().v,
        };
      });
}

template <typename Data>
QByteArray Pack(const Data &data) {
  const auto packed = Serialize(data);
  auto result = QByteArray();
  result.reserve(tl::count_length(packed));
  packed.write(result);
  return result;
}

template <typename Data, typename TLType = decltype(Serialize(std::declval<Data>()))>
Data Unpack(const QByteArray &data) {
  auto result = TLType();
  auto from = data.data();
  const auto till = from + data.size();
  return result.read(from, till) ? Deserialize(result) : Data();
}

}  // namespace

std::optional<Error> ErrorFromStorage(const Storage::Cache::Error &error) {
  using Type = Storage::Cache::Error::Type;
  if (error.type == Type::IO || error.type == Type::LockFailed) {
    return Error{Error::Type::IO, error.path};
  } else if (error.type == Type::WrongKey) {
    return Error{Error::Type::WrongPassword};
  }
  return std::nullopt;
}

void DeletePublicKey(not_null<RequestSender *> lib, const QByteArray &publicKey, const QByteArray &secret,
                     const Callback<> &done) {
  lib->request(TLDeleteKey(tl_key(tl_string(publicKey), TLsecureBytes{secret})))
      .done([=] { InvokeCallback(done); })
      .fail([=](const TLError &error) { InvokeCallback(done, ErrorFromLib(error)); })
      .send();
}

void SaveWalletList(not_null<Storage::Cache::Database *> db, const WalletList &list, bool useTestNetwork,
                    const Callback<> &done) {
  auto saved = [=](const Storage::Cache::Error &error) {
    crl::on_main([=] {
      if (const auto bad = ErrorFromStorage(error)) {
        InvokeCallback(done, *bad);
      } else {
        InvokeCallback(done);
      }
    });
  };
  if (list.entries.empty()) {
    db->remove(WalletListKey(useTestNetwork), std::move(saved));
  } else {
    db->put(WalletListKey(useTestNetwork), Pack(list), std::move(saved));
  }
}

void LoadWalletList(not_null<Storage::Cache::Database *> db, bool useTestNetwork, const Fn<void(WalletList &&)> &done) {
  Expects(done != nullptr);

  db->get(WalletListKey(useTestNetwork), [=](const QByteArray &value) {
    crl::on_main([done, result = Unpack<WalletList>(value)]() mutable { done(std::move(result)); });
  });
}

void SaveIgnoredAssetsList(not_null<Storage::Cache::Database *> db, bool useTestNetwork,
                           const IgnoredAssetsList &ignoredAssets, const Callback<> &done) {
  auto saved = [=](const Storage::Cache::Error &error) {
    crl::on_main([=] {
      if (const auto bad = ErrorFromStorage(error)) {
        InvokeCallback(done, *bad);
      } else {
        InvokeCallback(done);
      }
    });
  };
  if (ignoredAssets.list.empty()) {
    db->remove(IgnoredAssetsListKey(useTestNetwork), std::move(saved));
  } else {
    db->put(IgnoredAssetsListKey(useTestNetwork), Pack(ignoredAssets.list), std::move(saved));
  }
}

void LoadIgnoredAssetsList(not_null<Storage::Cache::Database *> db, bool useTestNetwork,
                           const Fn<void(IgnoredAssetsList &&)> &done) {
  Expects(done != nullptr);

  db->get(IgnoredAssetsListKey(useTestNetwork), [=](const QByteArray &value) {
    crl::on_main([done, result = Unpack<std::vector<IgnoredAssetListItem>>(value)]() mutable {
      done(IgnoredAssetsList{.list = std::move(result)});
    });
  });
}

void SaveTokenOwnersCache(not_null<Storage::Cache::Database *> db, bool useTestNetwork,
                          const QString &rootContractAddress, const TokenOwnersCache &owners, const Callback<> &done) {
  auto saved = [=](const Storage::Cache::Error &error) {
    crl::on_main([=] {
      if (const auto bad = ErrorFromStorage(error)) {
        InvokeCallback(done, *bad);
      } else {
        InvokeCallback(done);
      }
    });
  };
  if (owners.entries.empty()) {
    db->remove(TokenOwnersCacheKey(useTestNetwork, rootContractAddress), std::move(saved));
  } else {
    db->put(TokenOwnersCacheKey(useTestNetwork, rootContractAddress), Pack(owners), std::move(saved));
  }
}

void LoadTokenOwnersCache(not_null<Storage::Cache::Database *> db, bool useTestNetwork,
                          const QString &rootContractAddress, const Fn<void(TokenOwnersCache &&)> &done) {
  Expects(done != nullptr);

  db->get(TokenOwnersCacheKey(useTestNetwork, rootContractAddress), [=](const QByteArray &value) {
    crl::on_main([done, result = Unpack<TokenOwnersCache>(value)]() mutable { done(std::move(result)); });
  });
}

void SaveKnownTokenContracts(not_null<Storage::Cache::Database *> db, bool useTestNetwork,
                             const KnownTokenContracts &knownContracts, const Callback<> &done) {
  auto saved = [=](const Storage::Cache::Error &error) {
    crl::on_main([=] {
      if (const auto bad = ErrorFromStorage(error)) {
        InvokeCallback(done, *bad);
      } else {
        InvokeCallback(done);
      }
    });
  };
  if (knownContracts.addresses.empty()) {
    db->remove(KnownTokenContractsKey(useTestNetwork), std::move(saved));
  } else {
    db->put(KnownTokenContractsKey(useTestNetwork), Pack(knownContracts), std::move(saved));
  }
}

void LoadKnownTokenContracts(not_null<Storage::Cache::Database *> db, bool useTestNetwork,
                             const Fn<void(KnownTokenContracts &&)> &done) {
  Expects(done != nullptr);

  db->get(KnownTokenContractsKey(useTestNetwork), [=](const QByteArray &value) {
    crl::on_main([done, result = Unpack<KnownTokenContracts>(value)]() mutable { done(std::move(result)); });
  });
}

void SaveWalletState(not_null<Storage::Cache::Database *> db, const WalletState &state, Callback<> &&done) {
  if (state == WalletState{.address = state.address, .assetsList = {Ton::AssetListItemWallet{}}}) {
    InvokeCallback(done);
    return;
  }
  auto saved = [=, done = std::move(done)](const Storage::Cache::Error &error) mutable {
    crl::on_main([=, done = std::move(done)] {
      if (const auto bad = ErrorFromStorage(error)) {
        InvokeCallback(done, *bad);
      } else {
        InvokeCallback(done);
      }
    });
  };
  db->put(WalletStateKey(state.address), Pack(state), std::move(saved));
}

void LoadWalletState(not_null<Storage::Cache::Database *> db, const QString &address,
                     const Fn<void(WalletState &&)> &done) {
  Expects(done != nullptr);

  db->get(WalletStateKey(address), [=](const QByteArray &value) {
    crl::on_main([=, result = Unpack<WalletState>(value)]() mutable {
      done((result.address == address) ? std::move(result)
                                       : WalletState{.address = address, .assetsList = {Ton::AssetListItemWallet{}}});
    });
  });
}

void SaveSettings(not_null<Storage::Cache::Database *> db, const Settings &settings, const Callback<> &done) {
  auto saved = [=](const Storage::Cache::Error &error) {
    crl::on_main([=] {
      if (const auto bad = ErrorFromStorage(error)) {
        InvokeCallback(done, *bad);
      } else {
        InvokeCallback(done);
      }
    });
  };
  db->put(kSettingsKey, Pack(settings), std::move(saved));
}

void LoadSettings(not_null<Storage::Cache::Database *> db, const Fn<void(Settings &&)> &done) {
  Expects(done != nullptr);

  db->get(kSettingsKey, [=](const QByteArray &value) {
    crl::on_main([=, result = Unpack<Settings>(value)]() mutable { done(std::move(result)); });
  });
}

}  // namespace Ton::details
