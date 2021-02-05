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

[[nodiscard]] Storage::Cache::Key WalletListKey(bool useTestNetwork) {
  return useTestNetwork ? kWalletTestListKey : kWalletMainListKey;
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

TLstorage_Bool Serialize(const bool &data);
bool Deserialize(const TLstorage_Bool &data);
TLstorage_WalletEntry Serialize(const WalletList::Entry &data);
WalletList::Entry Deserialize(const TLstorage_WalletEntry &data);
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
TLstorage_AssetsListItem Serialize(const AssetListItem &data);
AssetListItem Deserialize(const TLstorage_AssetsListItem &data);
TLstorage_WalletState Serialize(const WalletState &data);
WalletState Deserialize(const TLstorage_WalletState &data);
TLstorage_TokenOwnersCache Serialize(const TokenOwnersCache &data);
TokenOwnersCache Deserialize(const TLstorage_TokenOwnersCache &data);
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

WalletList::Entry Deserialize(const TLstorage_WalletEntry &data) {
  return data.match(
      [&](const TLDstorage_walletEntry &data) {
        return WalletList::Entry{
            .publicKey = data.vpublicKey().v,
            .secret = data.vsecret().v,
        };
      },
      [&](const TLDstorage_walletEntryGeneric &data) {
        return WalletList::Entry{
            .publicKey = data.vpublicKey().v,
            .secret = data.vsecret().v,
            .address = tl::utf16(data.vaddress()),
        };
      });
}

TLstorage_WalletList Serialize(const WalletList &data) {
  return make_storage_walletList(Serialize(data.entries));
}

WalletList Deserialize(const TLstorage_WalletList &data) {
  auto result = WalletList();
  data.match([&](const TLDstorage_walletList &data) { result.entries = Deserialize(data.ventries()); });
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
  return make_storage_message2(tl_string(data.source), tl_string(data.destination), tl_int64(data.value),
                               tl_int64(data.created), tl_bytes(data.bodyHash), Serialize(data.message),
                               Serialize(data.bounce));
}

Message Deserialize(const TLstorage_Message &data) {
  return data.match(
      [&](const TLDstorage_message &data) {
        return Message{tl::utf16(data.vsource()),
                       tl::utf16(data.vdestination()),
                       data.vvalue().v,
                       data.vcreated().v,
                       data.vbodyHash().v,
                       MessageData{tl::utf16(data.vmessage())},
                       false};
      },
      [&](const TLDstorage_message2 &data) {
        return Message{tl::utf16(data.vsource()),
                       tl::utf16(data.vdestination()),
                       data.vvalue().v,
                       data.vcreated().v,
                       data.vbodyHash().v,
                       Deserialize(data.vmessage()),
                       Deserialize(data.vbounce())};
      });
}

TLstorage_Transaction Serialize(const Transaction &data) {
  return make_storage_transaction(Serialize(data.id), tl_int64(data.time), tl_int64(data.fee),
                                  tl_int64(data.storageFee), tl_int64(data.otherFee), Serialize(data.incoming),
                                  Serialize(data.outgoing), Serialize(data.aborted));
}

Transaction Deserialize(const TLstorage_Transaction &data) {
  return data.match([&](const TLDstorage_transaction &data) {
    return Transaction{Deserialize(data.vid()),
                       data.vtime().v,
                       data.vfee().v,
                       data.vstorageFee().v,
                       data.votherFee().v,
                       Deserialize(data.vincoming()),
                       Deserialize(data.voutgoing()),
                       Deserialize(data.vaborted())};
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
  return make_storage_tokenState(tl_string(data.token.rootContractAddress()), tl_string(data.walletContractAddress),
                                 tl_string(data.token.rootContractAddress()), tl_string(data.token.name()),
                                 tl_int32(static_cast<int32_t>(data.token.decimals())),
                                 Serialize(data.lastTransactions), tl_int64(data.balance));
}

TokenState Deserialize(const TLstorage_TokenState &data) {
  return data.match([&](const TLDstorage_tokenState &data) {
    return TokenState{.token = Symbol::tip3(tl::utf8(data.vname().v), static_cast<size_t>(data.vdecimals().v),
                                            data.vrootContractAddress().v),
                      .walletContractAddress = data.vwalletContractAddress().v,
                      .rootOwnerAddress = data.vrootOwnerAddress().v,
                      .lastTransactions = Deserialize(data.vlastTransactions()),
                      .balance = data.vbalance().v};
  });
}

TLstorage_DePoolState Serialize(const NamedDePoolState &data) {
  return make_storage_dePoolState(tl_string(data.address), tl_int64(data.state.total),
                                  tl_int64(data.state.withdrawValue), Serialize(data.state.reinvest),
                                  tl_int64(data.state.reward));
}

NamedDePoolState Deserialize(const TLstorage_DePoolState &data) {
  return data.match([&](const TLDstorage_dePoolState &data) {
    auto address = QString::fromUtf8(data.vaddress().v);
    auto state = DePoolParticipantState{.total = data.vtotal().v,
                                        .withdrawValue = data.vwithdrawValue().v,
                                        .reinvest = Deserialize(data.vreinvest()),
                                        .reward = data.vreward().v};
    return NamedDePoolState{std::move(address), state};
  });
}

TLstorage_AssetsListItem Serialize(const AssetListItem &data) {
  return v::match(
      data, [](const AssetListItemWallet &) { return make_storage_assetsListMain(); },
      [](const AssetListItemToken &item) {
        return make_storage_assetsListToken(tl_string(item.symbol.name()), tl_int32(item.symbol.decimals()),
                                            tl_string(item.symbol.rootContractAddress()));
      },
      [](const AssetListItemDePool &item) { return make_storage_assetsListDePool(tl_string(item.address)); });
}

AssetListItem Deserialize(const TLstorage_AssetsListItem &data) {
  return data.match([](const TLDstorage_assetsListMain &) -> AssetListItem { return AssetListItemWallet{}; },
                    [](const TLDstorage_assetsListToken &data) -> AssetListItem {
                      return AssetListItemToken{.symbol = Symbol::tip3(tl::utf8(data.vname().v), data.vdecimals().v,
                                                                       tl::utf8(data.vrootContractAddress().v))};
                    },
                    [](const TLDstorage_assetsListDePool &data) -> AssetListItem {
                      return AssetListItemDePool{.address = tl::utf8(data.vaddress().v)};
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

  return make_storage_walletState(tl_string(data.address), Serialize(data.account), Serialize(data.lastTransactions),
                                  Serialize(data.pendingTransactions), Serialize(tokenStates), Serialize(depoolStates),
                                  Serialize(data.assetsList));
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
    std::map<QString, DePoolParticipantState> depoolStates;
    for (auto &item : storedDePoolStates) {
      depoolStates.emplace(item.address, item.state);
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
                       .assetsList = std::move(assetsList)};
  });
}

TLstorage_TokenOwnersCache Serialize(const TokenOwnersCache &data) {
  TLvector<TLstorage_tokenOwnersCacheItem> wallets;
  wallets.v.reserve(data.entries.size());
  for (const auto &[owner, wallet] : data.entries) {
    wallets.v.push_back(make_storage_tokenOwnersCacheItem(tl_string(owner), tl_string(wallet)));
  }
  return make_storage_tokenOwnersCache(wallets);
}

TokenOwnersCache Deserialize(const TLstorage_TokenOwnersCache &data) {
  TokenOwnersCache owners;
  for (const auto &item : data.c_storage_tokenOwnersCache().vwallets().v) {
    const auto &wallet = item.c_storage_tokenOwnersCacheItem();
    owners.entries.emplace(std::piecewise_construct, std::forward_as_tuple(wallet.vowner().v),
                           std::forward_as_tuple(wallet.vwallet().v));
  }
  return owners;
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
  auto result = Settings();
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
  return result;
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
                     Callback<> done) {
  lib->request(TLDeleteKey(tl_key(tl_string(publicKey), TLsecureBytes{secret})))
      .done([=] { InvokeCallback(done); })
      .fail([=](const TLError &error) { InvokeCallback(done, ErrorFromLib(error)); })
      .send();
}

void SaveWalletList(not_null<Storage::Cache::Database *> db, const WalletList &list, bool useTestNetwork,
                    Callback<> done) {
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

void LoadWalletList(not_null<Storage::Cache::Database *> db, bool useTestNetwork, Fn<void(WalletList &&)> done) {
  Expects(done != nullptr);

  db->get(WalletListKey(useTestNetwork), [=](QByteArray value) {
    crl::on_main([done, result = Unpack<WalletList>(value)]() mutable { done(std::move(result)); });
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

void SaveWalletState(not_null<Storage::Cache::Database *> db, const WalletState &state, const Callback<> &done) {
  if (state == WalletState{.address = state.address, .assetsList = {Ton::AssetListItemWallet{}}}) {
    InvokeCallback(done);
    return;
  }
  auto saved = [=](const Storage::Cache::Error &error) {
    crl::on_main([=] {
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
