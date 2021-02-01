// This file is part of Desktop App Toolkit,
// a set of libraries for developing nice desktop applications.
//
// For license and copyright information please follow this link:
// https://github.com/desktop-app/legal/blob/master/LEGAL
//
#pragma once

#include "ton/ton_settings.h"

#include <unordered_map>

#include <QHash>
#include <utility>

namespace Ton {

inline constexpr auto kUnknownBalance = int64(-666);

struct ConfigInfo {
  int64 walletId = 0;
  QByteArray restrictedInitPublicKey;
};

struct TransactionId {
  int64 lt = 0;
  QByteArray hash;
};

enum class CurrencyKind {
  TON,
  TIP3,
};

class Symbol {
 public:
  static auto ton() -> Symbol {
    return Symbol{};
  }

  static auto tip3(const QString &name, size_t decimals) -> Symbol {
    return Symbol(CurrencyKind::TIP3, name, decimals);
  }

  Symbol() noexcept : kind_{CurrencyKind::TON}, name_{"TON"}, decimals_{9} {
  }

  auto kind() const -> CurrencyKind {
    return kind_;
  }

  auto name() const -> const QString & {
    return name_;
  }

  auto decimals() const -> const size_t {
    return decimals_;
  }

  auto isTon() const -> bool {
    return kind_ == CurrencyKind::TON;
  }

  auto isToken() const -> bool {
    return kind_ == CurrencyKind::TIP3;
  }

 private:
  Symbol(CurrencyKind kind, QString name, size_t decimals) noexcept
      : kind_{kind}, name_{std::move(name)}, decimals_{decimals} {
  }

  CurrencyKind kind_;
  QString name_;
  size_t decimals_;
};

bool operator==(const Symbol &a, const Symbol &b);
bool operator!=(const Symbol &a, const Symbol &b);
bool operator<(const Symbol &a, const Symbol &b);

template <typename T>
using CurrencyMap = std::map<Symbol, T>;

bool operator==(const TransactionId &a, const TransactionId &b);

bool operator!=(const TransactionId &a, const TransactionId &b);

bool operator<(const TransactionId &a, const TransactionId &b);

struct RestrictionLimit {
  int32 seconds = 0;
  int64 lockedAmount = 0;
};

bool operator==(const RestrictionLimit &a, const RestrictionLimit &b);

bool operator!=(const RestrictionLimit &a, const RestrictionLimit &b);

struct AccountState {
  int64 fullBalance = kUnknownBalance;
  int64 lockedBalance = 0;
  int64 syncTime = 0;
  int64 restrictionStartAt = 0;
  TransactionId lastTransactionId;
  std::vector<RestrictionLimit> restrictionLimits;
};

bool operator==(const AccountState &a, const AccountState &b);

bool operator!=(const AccountState &a, const AccountState &b);

struct RootTokenContractDetails {
  QString name;
  QString symbol;
  int64 decimals{};
  int64 startGasBalance;
};

struct InvestParams {
  int64 remainingAmount{};
  int64 lastWithdrawalTime{};
  int32 withdrawalPeriod{};
  int64 withdrawalValue{};
  QString owner{};
};

bool operator==(const InvestParams &a, const InvestParams &b);

bool operator!=(const InvestParams &a, const InvestParams &b);

struct DePoolParticipantState {
  int64 total = 0;
  int64 withdrawValue = 0;
  bool reinvest = false;
  int64 reward = 0;
  std::map<int64, int64> stakes{};
  std::map<int64, InvestParams> vestings{};
  std::map<int64, InvestParams> locks{};
};

bool operator==(const DePoolParticipantState &a, const DePoolParticipantState &b);

bool operator!=(const DePoolParticipantState &a, const DePoolParticipantState &b);

using DePoolStatesMap = std::map<QString, DePoolParticipantState>;

enum class MessageDataType { PlainText, EncryptedText, DecryptedText, RawBody };

struct TokenTransfer {
  QString address;
  int64 value{};
  bool incoming{};
};

struct TokenSwapBack {
  QString address;
  int64 value{};
};

using TokenTransaction = std::variant<TokenTransfer, TokenSwapBack>;

struct DePoolOrdinaryStakeTransaction {
  int64 stake = 0;
};

struct DePoolOnRoundCompleteTransaction {
  int64 roundId{};
  int64 reward{};
  int64 ordinaryStake{};
  int64 vestingStake{};
  int64 lockStake{};
  bool reinvest{};
  uint8 reason{};
};

using DePoolTransaction = std::variant<DePoolOrdinaryStakeTransaction, DePoolOnRoundCompleteTransaction>;

struct MessageData {
  QString text;
  QByteArray data;
  MessageDataType type;
};

struct Message {
  QString source;
  QString destination;
  int64 value = 0;
  int64 created = 0;
  QByteArray bodyHash;
  MessageData message;
};

struct EncryptedText {
  QByteArray bytes;
  QString source;
};

struct DecryptedText {
  QString text;
  QByteArray proof;
};

struct Transaction {
  TransactionId id;
  int64 time = 0;
  int64 fee = 0;
  int64 storageFee = 0;
  int64 otherFee = 0;
  Message incoming;
  std::vector<Message> outgoing;
  bool initializing = false;
};

bool operator==(const Transaction &a, const Transaction &b);

bool operator!=(const Transaction &a, const Transaction &b);

struct TransactionsSlice {
  std::vector<Transaction> list;
  TransactionId previousId;
};

bool operator==(const TransactionsSlice &a, const TransactionsSlice &b);

bool operator!=(const TransactionsSlice &a, const TransactionsSlice &b);

struct TokenState {
  Symbol token;
  QString rootContractAddress;
  QString walletContractAddress;
  TransactionsSlice lastTransactions;
  int64 balance = kUnknownBalance;
};

bool operator==(const TokenState &a, const TokenState &b);

bool operator!=(const TokenState &a, const TokenState &b);

struct TokenStateValue {
  QString rootContractAddress;
  QString walletContractAddress;
  TransactionsSlice lastTransactions;
  int64 balance = kUnknownBalance;

  [[nodiscard]] auto withSymbol(Symbol symbol) const -> TokenState {
    return TokenState{.token = std::move(symbol),
                      .rootContractAddress = rootContractAddress,
                      .walletContractAddress = walletContractAddress,
                      .lastTransactions = lastTransactions,
                      .balance = balance};
  }
};

bool operator==(const TokenStateValue &a, const TokenStateValue &b);

bool operator!=(const TokenStateValue &a, const TokenStateValue &b);

struct TransactionToSend {
  int64 amount = 0;
  QString recipient;
  QString comment;
  int timeout = 0;
  bool allowSendToUninited = false;
  bool sendUnencryptedText = false;
};

struct TokenTransactionToSend {
  constexpr static int64 realAmount = 500'000'000;  // 0.5 TON
  QString walletContractAddress;
  int64 amount = 0;
  QString recipient;
  int timeout = 0;
  bool swapBack = false;
};

struct DeployTokenWalletTransactionToSend {
  constexpr static int64 realAmount = 500'000'000;      // 0.5 TON
  constexpr static int64 initialBalance = 100'000'000;  // 0.1 TON
  static_assert(realAmount > initialBalance);

  QString rootContractAddress;
  QString walletContractAddress;
  int timeout = 0;
};

struct StakeTransactionToSend {
  constexpr static int64 depoolFee = 500'000'000;  // 0.5 TON
  int64 stake = 0;
  QString depoolAddress;
  int timeout = 0;
};

struct WithdrawalTransactionToSend {
  constexpr static int64 depoolFee = 500'000'000;  // 0.5 TON
  int64 amount = 0;
  bool all = 0;
  QString depoolAddress;
  int timeout = 0;
};

struct CancelWithdrawalTransactionToSend {
  constexpr static int64 depoolFee = 500'000'000;  // 0.5 TON
  QString depoolAddress;
  int timeout = 0;
};

struct TransactionFees {
  int64 inForward = 0;
  int64 storage = 0;
  int64 gas = 0;
  int64 forward = 0;

  [[nodiscard]] int64 sum() const;
};

struct TransactionCheckResult {
  TransactionFees sourceFees;
  std::vector<TransactionFees> destinationFees;
};

struct PendingTransaction {
  Transaction fake;
  int64 sentUntilSyncTime = 0;
};

bool operator==(const PendingTransaction &a, const PendingTransaction &b);
bool operator!=(const PendingTransaction &a, const PendingTransaction &b);

struct AssetListItemWallet {};
struct AssetListItemToken {
  Symbol symbol;
};
struct AssetListItemDePool {
  QString address;
};

using AssetListItem = std::variant<AssetListItemWallet, AssetListItemToken, AssetListItemDePool>;

bool operator==(const AssetListItem &a, const AssetListItem &b);
bool operator!=(const AssetListItem &a, const AssetListItem &b);

struct WalletState {
  QString address;
  AccountState account;
  TransactionsSlice lastTransactions;
  std::vector<PendingTransaction> pendingTransactions;
  std::map<Symbol, TokenStateValue> tokenStates;
  std::map<QString, DePoolParticipantState> dePoolParticipantStates;
  std::vector<AssetListItem> assetsList;
};

bool operator==(const WalletState &a, const WalletState &b);
bool operator!=(const WalletState &a, const WalletState &b);

struct WalletViewerState {
  WalletState wallet;
  crl::time lastRefresh = 0;
  bool refreshing = false;
};

struct LoadedSlice {
  TransactionId after;
  TransactionsSlice data;
};

struct SyncState {
  int from = 0;
  int to = 0;
  int current = 0;

  bool valid() const;
};

bool operator==(const SyncState &a, const SyncState &b);

bool operator!=(const SyncState &a, const SyncState &b);

struct LiteServerQuery {
  int64 id = 0;
  QByteArray bytes;
};

struct DecryptPasswordNeeded {
  QByteArray publicKey;
  int generation = 0;
};

struct DecryptPasswordGood {
  int generation = 0;
};

struct Update {
  std::variant<SyncState, LiteServerQuery, ConfigUpgrade, DecryptPasswordNeeded, DecryptPasswordGood> data;
};

}  // namespace Ton

namespace std {
template <>
struct hash<QString> {
  std::size_t operator()(const QString &s) const noexcept {
    return static_cast<size_t>(qHash(s));
  }
};

template <>
struct hash<Ton::Symbol> {
  std::size_t operator()(Ton::Symbol const &s) const noexcept {
    if (s.kind() == Ton::CurrencyKind::TON) {
      return 0;
    } else {
      return static_cast<std::size_t>(qHash(s.name())) + s.decimals();
    }
  }
};

}  // namespace std
