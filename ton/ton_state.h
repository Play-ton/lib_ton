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

#include <boost/multiprecision/cpp_int.hpp>

namespace Ton {

inline constexpr auto kUnknownBalance = int64(-666);

inline constexpr auto kFtabiKeyDerivationPath = "m/44'/396'/0'/0/0";
inline constexpr auto kMaxMultisigCustodianCount = 32;
inline constexpr int64 kMinimalDeploymentBalance = 500'000'000;  // 0.5 TON

extern const QString kZeroAddress;

using int128 = boost::multiprecision::int128_t;

struct ConfigInfo {
  int64 walletId = 0;
  QByteArray restrictedInitPublicKey;
};

enum class KeyType {
  Original,
  Ftabi,
};

struct FtabiKey {
  QString name;
  QByteArray publicKey;
};

struct AvailableKey {
  Ton::KeyType type;
  QByteArray publicKey;
  QString name;
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

  static auto tip3(const QString &name, size_t decimals, const QString &rootContractAddress) -> Symbol {
    return Symbol(CurrencyKind::TIP3, name, decimals, rootContractAddress);
  }

  Symbol() noexcept : _kind{CurrencyKind::TON}, _name{"TON"}, _decimals{9} {
  }

  auto kind() const -> CurrencyKind {
    return _kind;
  }

  auto name() const -> const QString & {
    return _name;
  }

  auto decimals() const -> size_t {
    return _decimals;
  }

  auto rootContractAddress() const -> const QString & {
    return _rootContractAddress;
  }

  auto isTon() const -> bool {
    return _kind == CurrencyKind::TON;
  }

  auto isToken() const -> bool {
    return _kind == CurrencyKind::TIP3;
  }

  auto toString() const -> QString;

  auto operator<(const Symbol &other) const -> bool;

 private:
  Symbol(CurrencyKind kind, QString name, size_t decimals, QString rootContractAddress) noexcept
      : _kind{kind}, _name{std::move(name)}, _decimals{decimals}, _rootContractAddress{rootContractAddress} {
  }

  CurrencyKind _kind;
  QString _name;
  size_t _decimals;
  QString _rootContractAddress;
};

bool operator==(const Symbol &a, const Symbol &b);
bool operator!=(const Symbol &a, const Symbol &b);

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
  bool isDeployed = false;
};

bool operator==(const AccountState &a, const AccountState &b);
bool operator!=(const AccountState &a, const AccountState &b);

struct RootTokenContractDetails {
  QString name;
  QString symbol;
  int64 decimals{};
  QString ownerAddress{};
  int64 startGasBalance;
};

struct TokenWalletContractDetails {
  QString rootAddress;
  QString ownerAddress;
};

enum class EthEventStatus { InProcess, Confirmed, Executed, Rejected };
enum class TonEventStatus { InProcess, Confirmed, Rejected };

struct EthEventDetails {
  QString rootTokenContract;
  EthEventStatus status;
  uint16 requiredConfirmationCount{};
  uint16 requiredRejectionCount{};
  uint16 confirmationCount{};
  uint16 rejectionCount{};
};

struct TonEventDetails {
  QString rootTokenContract;
  TonEventStatus status;
  uint16 requiredConfirmationCount{};
  uint16 requiredRejectionCount{};
  uint16 confirmationCount{};
  uint16 rejectionCount{};
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
  int32 version = 0;
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

struct TokenWalletDeployed {
  QString rootTokenContract;
};

struct EthEventStatusChanged {
  EthEventStatus status;
};

struct TonEventStatusChanged {
  TonEventStatus status;
};

struct TokenTransfer {
  QString address;
  int128 value{};
  bool incoming{};
  bool direct{};
};

struct TokenSwapBack {
  QString address;
  int128 value{};
};

struct TokenMint {
  int128 value{};
};

struct TokensBounced {
  int128 amount;
};

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

struct MultisigDeploymentTransaction {
  // TODO: add deployment info?
};

struct MultisigSubmitTransaction {
  QString dest;
  int64 amount;
  int64 transactionId;
  bool bounce;
  bool executed;
  QString comment;
};

struct MultisigConfirmTransaction {
  int64 transactionId;
  bool executed;
};

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
  bool bounce{};
  bool bounced{};
};

struct EncryptedText {
  QByteArray bytes;
  QString source;
};

struct DecryptedText {
  QString text;
  QByteArray proof;
};

struct RegularTransaction {};

using TransactionAdditionalInfo =     //
    std::variant<RegularTransaction,  //

                 // Events
                 TokenWalletDeployed,    //
                 EthEventStatusChanged,  //
                 TonEventStatusChanged,  //

                 // Token transaction
                 TokenTransfer,  //
                 TokenSwapBack,  //
                 TokenMint,      //
                 TokensBounced,  //

                 // DePool transaction
                 DePoolOrdinaryStakeTransaction,    //
                 DePoolOnRoundCompleteTransaction,  //

                 // Multisig transaction
                 MultisigDeploymentTransaction,  //
                 MultisigSubmitTransaction,      //
                 MultisigConfirmTransaction>;

struct Transaction {
  TransactionId id;
  int64 time = 0;
  int64 fee = 0;
  int64 storageFee = 0;
  int64 otherFee = 0;
  Message incoming;
  std::vector<Message> outgoing;
  bool aborted = false;
  TransactionAdditionalInfo additional = RegularTransaction{};
};

bool operator==(const Transaction &a, const Transaction &b);

bool operator!=(const Transaction &a, const Transaction &b);

struct TransactionsSlice {
  std::vector<Transaction> list;
  TransactionId previousId;
};

bool operator==(const TransactionsSlice &a, const TransactionsSlice &b);

bool operator!=(const TransactionsSlice &a, const TransactionsSlice &b);

enum class TokenVersion {
  tipo3v0,
  tipo3v1,
};

struct TokenState {
  Symbol token;
  TokenVersion version;
  QString walletContractAddress;
  QString rootOwnerAddress;
  TransactionsSlice lastTransactions;
  int128 balance{};
};

bool operator==(const TokenState &a, const TokenState &b);
bool operator!=(const TokenState &a, const TokenState &b);

struct TokenStateValue {
  TokenVersion version;
  QString walletContractAddress;
  QString rootOwnerAddress;
  TransactionsSlice lastTransactions;
  int128 balance{};

  [[nodiscard]] auto withSymbol(Symbol symbol) const -> TokenState {
    return TokenState{.token = std::move(symbol),
                      .version = version,
                      .walletContractAddress = walletContractAddress,
                      .rootOwnerAddress = rootOwnerAddress,
                      .lastTransactions = lastTransactions,
                      .balance = balance};
  }
};

bool operator==(const TokenStateValue &a, const TokenStateValue &b);
bool operator!=(const TokenStateValue &a, const TokenStateValue &b);

enum class MultisigVersion {
  SafeMultisig,
  SafeMultisig24h,
  SetcodeMultisig,
  Surf,
};

int GetExpirationTime(MultisigVersion version);

struct MultisigInitialInfo {
  QString address;
  MultisigVersion version;
  QByteArray publicKey;
  QByteArray initState;
};

struct MultisigPredeployInfo {
  int64 balance;
  MultisigInitialInfo initialInfo;
};

struct MultisigInfo {
  QString address;
  MultisigVersion version;
  QByteArray publicKey;
  std::vector<QByteArray> custodians;
  int64 expirationTime;
};

struct TransactionToSend {
  int64 amount = 0;
  QString recipient;
  QString comment;
  int timeout = 0;
  bool allowSendToUninited = false;
};

enum class TokenTransferType {
  Direct,
  ToOwner,
  SwapBack,
};

struct TokenTransactionToSend {
  constexpr static int64 realAmount = 500'000'000;      // 0.5 TON
  constexpr static int64 initialBalance = 100'000'000;  // 0.1 TON
  static_assert(realAmount > initialBalance);

  QString rootContractAddress;
  QString walletContractAddress;
  int128 amount = 0;
  QString recipient;
  QString callbackAddress;
  int timeout = 0;
  TokenTransferType tokenTransferType = TokenTransferType::Direct;
};

struct DeployTokenWalletTransactionToSend {
  constexpr static int64 realAmount = 500'000'000;      // 0.5 TON
  constexpr static int64 initialBalance = 100'000'000;  // 0.1 TON
  static_assert(realAmount > initialBalance);

  QString rootContractAddress;
  QString walletContractAddress;
  int timeout = 0;
};

struct CollectTokensTransactionToSend {
  constexpr static int64 realAmount = 1'000'000'000;  // 1 TON

  QString eventContractAddress;
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

struct DeployMultisigTransactionToSend {
  MultisigInitialInfo initialInfo;
  uint8 requiredConfirmations = 1;
  std::vector<QByteArray> owners;
  int timeout = 0;
};

struct SubmitTransactionToSend {
  QByteArray publicKey;
  QString multisigAddress;
  QString dest;
  int64 value;
  bool bounce;
  QString comment;
  int timeout = 0;
};

struct ConfirmTransactionToSend {
  QByteArray publicKey;
  QString multisigAddress;
  int64 transactionId;
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

struct InvalidEthAddress {};
struct TokenTransferUnchanged {};
struct DirectAccountNotFound {};
struct DirectRecipient {
  QString address;
};

using TokenTransferCheckResult =
    std::variant<InvalidEthAddress, TokenTransferUnchanged, DirectAccountNotFound, DirectRecipient>;

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
struct AssetListItemMultisig {
  QString address;
};

using AssetListItem = std::variant<AssetListItemWallet, AssetListItemToken, AssetListItemDePool, AssetListItemMultisig>;

bool operator==(const AssetListItem &a, const AssetListItem &b);
bool operator!=(const AssetListItem &a, const AssetListItem &b);

struct IgnoredAssetToken {
  QString rootTokensContractAddress;
};
struct IgnoredAssetDePool {
  QString address;
};

using IgnoredAssetListItem = std::variant<IgnoredAssetToken, IgnoredAssetDePool>;

bool operator==(const IgnoredAssetListItem &a, const IgnoredAssetListItem &b);
bool operator!=(const IgnoredAssetListItem &a, const IgnoredAssetListItem &b);

struct IgnoredAsset {
  IgnoredAssetListItem data;
};

struct IgnoredAssetsList {
  std::vector<IgnoredAssetListItem> list;
};

struct MultisigState {
  MultisigVersion version;
  QByteArray publicKey;
  AccountState accountState;
  TransactionsSlice lastTransactions;
  std::vector<PendingTransaction> pendingTransactions;

  std::vector<QByteArray> custodians;
  int64 expirationTime;
};

bool operator==(const MultisigState &a, const MultisigState &b);
bool operator!=(const MultisigState &a, const MultisigState &b);

using MultisigStatesMap = std::map<QString, MultisigState>;

struct WalletState {
  QString address;
  AccountState account;
  TransactionsSlice lastTransactions;
  std::vector<PendingTransaction> pendingTransactions;
  std::map<Symbol, TokenStateValue> tokenStates;
  std::map<QString, DePoolParticipantState> dePoolParticipantStates;
  std::map<QString, MultisigState> multisigStates;
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

QByteArray Int128ToBytesBE(const int128 &from);
int128 BytesBEToInt128(const QByteArray &from);

template <typename T, typename D>
auto SelectField(T D::*field) -> Fn<T &(D &)> {
  return field;
}

template <typename T, typename D>
auto SelectConstField(T D::*field) -> Fn<const T &(const D &)> {
  return field;
}

}  // namespace Ton

namespace std {
namespace details {

template <typename T, typename... Rest>
void hash_combine(uint &seed, const T &v, Rest... rest) {
  seed ^= qHash(v) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
  (hash_combine(seed, rest), ...);
}

}  // namespace details

template <>
struct hash<QString> {
  std::size_t operator()(const QString &s) const noexcept {
    return static_cast<size_t>(qHash(s));
  }
};

template <>
struct hash<Ton::Symbol> {
  size_t operator()(Ton::Symbol const &s) const noexcept {
    if (s.kind() == Ton::CurrencyKind::TON) {
      return 0;
    } else {
      uint hash{};
      details::hash_combine(hash, s.name(), s.decimals(), s.rootContractAddress());
      return static_cast<std::size_t>(hash);
    }
  }
};

}  // namespace std
