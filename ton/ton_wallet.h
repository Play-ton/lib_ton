// This file is part of Desktop App Toolkit,
// a set of libraries for developing nice desktop applications.
//
// For license and copyright information please follow this link:
// https://github.com/desktop-app/legal/blob/master/LEGAL
//
#pragma once

#include "ton/ton_result.h"
#include "ton/ton_state.h"
#include "base/weak_ptr.h"
#include "base/timer.h"

#include <unordered_set>

namespace tl {
template <typename>
class boxed;
}  // namespace tl

namespace Storage::Cache {
class Database;
}  // namespace Storage::Cache

namespace Ton {
namespace details {
struct WalletList;
class External;
class KeyCreator;
class KeyDestroyer;
class PasswordChanger;
class AccountViewers;
class WebLoader;
class LocalTimeSyncer;
struct BlockchainTime;
class TLerror;
class TLinputKey;
class TLmsg_data;
struct UnpackedAddress;
}  // namespace details

struct Settings;
class AccountViewer;

class Wallet final : public base::has_weak_ptr {
 public:
  explicit Wallet(const QString &path);
  ~Wallet();

  void open(const QByteArray &globalPassword, const Settings &defaultSettings, const Callback<> &done);
  void start(const Callback<> &done);
  [[nodiscard]] QString getUsedAddress(const QByteArray &publicKey) const;
  void checkConfig(const QByteArray &config, const Callback<> &done);

  void sync();

  [[nodiscard]] const Settings &settings() const;
  void updateSettings(Settings settings, const Callback<> &done);

  [[nodiscard]] rpl::producer<Update> updates() const;

  [[nodiscard]] std::vector<QByteArray> publicKeys() const;

  void createKey(const Callback<std::vector<QString>> &done);
  void importKey(const std::vector<QString> &words, const Callback<> &done);
  void queryWalletAddress(const Callback<QString> &done);
  void saveKey(const QByteArray &password, const QString &address, const Callback<QByteArray> &done);
  void exportKey(const QByteArray &publicKey, const QByteArray &password, const Callback<std::vector<QString>> &done);
  void deleteKey(const QByteArray &publicKey, const Callback<> &done);
  void deleteAllKeys(const Callback<> &done);
  void changePassword(const QByteArray &oldPassword, const QByteArray &newPassword, const Callback<> &done);

  void checkSendGrams(const QByteArray &publicKey, const TransactionToSend &transaction,
                      const Callback<TransactionCheckResult> &done);

  void checkSendTokens(const QByteArray &publicKey, const TokenTransactionToSend &transaction,
                       const Callback<std::pair<TransactionCheckResult, TokenTransferCheckResult>> &done);

  void checkSendStake(const QByteArray &publicKey, const StakeTransactionToSend &transaction,
                      const Callback<TransactionCheckResult> &done);

  void checkWithdraw(const QByteArray &publicKey, const WithdrawalTransactionToSend &transaction,
                     const Callback<TransactionCheckResult> &done);

  void checkCancelWithdraw(const QByteArray &publicKey, const CancelWithdrawalTransactionToSend &transaction,
                           const Callback<TransactionCheckResult> &done);

  void checkDeployTokenWallet(const QByteArray &publicKey, const DeployTokenWalletTransactionToSend &transaction,
                              const Callback<TransactionCheckResult> &done);

  void checkCollectTokens(const QByteArray &publicKey, const CollectTokensTransactionToSend &transaction,
                          const Callback<TransactionCheckResult> &done);

  void sendGrams(const QByteArray &publicKey, const QByteArray &password, const TransactionToSend &transaction,
                 const Callback<PendingTransaction> &ready, const Callback<> &done);

  void sendTokens(const QByteArray &publicKey, const QByteArray &password, const TokenTransactionToSend &transaction,
                  const Callback<PendingTransaction> &ready, const Callback<> &done);

  void sendStake(const QByteArray &publicKey, const QByteArray &password, const StakeTransactionToSend &transaction,
                 const Callback<PendingTransaction> &ready, const Callback<> &done);

  void withdraw(const QByteArray &publicKey, const QByteArray &password, const WithdrawalTransactionToSend &transaction,
                const Callback<PendingTransaction> &ready, const Callback<> &done);

  void cancelWithdrawal(const QByteArray &publicKey, const QByteArray &password,
                        const CancelWithdrawalTransactionToSend &transaction, const Callback<PendingTransaction> &ready,
                        const Callback<> &done);

  void deployTokenWallet(const QByteArray &publicKey, const QByteArray &password,
                         const DeployTokenWalletTransactionToSend &transaction,
                         const Callback<PendingTransaction> &ready, const Callback<> &done);

  void collectTokens(const QByteArray &publicKey, const QByteArray &password,
                     const CollectTokensTransactionToSend &transaction, const Callback<PendingTransaction> &ready,
                     const Callback<> &done);

  void openGate(const QString &rawAddress, const std::optional<Symbol> &token = {});
  void openReveal(const QString &rawAddress, const QString &ethereumAddress);

  void addDePool(const QByteArray &publicKey, const QString &dePoolAddress, const Callback<> &done);
  void removeDePool(const QByteArray &publicKey, const QString &dePoolAddress);

  void addToken(const QByteArray &publicKey, const QString &rootContractAddress, const Callback<> &done);
  void removeToken(const QByteArray &publicKey, const Symbol &token);
  void reorderAssets(const QByteArray &publicKey, int oldPosition, int newPosition);

  static void EnableLogging(bool enabled, const QString &basePath);
  static void LogMessage(const QString &message);
  [[nodiscard]] static bool CheckAddress(const QString &address);
  [[nodiscard]] static QString ConvertIntoRaw(const QString &address);
  [[nodiscard]] static QString ConvertIntoPacked(const QString &address);
  [[nodiscard]] static std::optional<Ton::TokenTransaction> ParseTokenTransaction(const Ton::MessageData &message);
  [[nodiscard]] static std::optional<Ton::DePoolTransaction> ParseDePoolTransaction(const Ton::MessageData &message,
                                                                                    bool incoming);
  [[nodiscard]] static std::optional<Ton::Notification> ParseNotification(const Ton::MessageData &message);
  [[nodiscard]] static base::flat_set<QString> GetValidWords();
  [[nodiscard]] static bool IsIncorrectPasswordError(const Error &error);

  [[nodiscard]] std::unique_ptr<AccountViewer> createAccountViewer(const QByteArray &publicKey, const QString &address);
  void updateViewersPassword(const QByteArray &publicKey, const QByteArray &password);

  void loadWebResource(const QString &url, Callback<QByteArray> done);

  void decrypt(const QByteArray &publicKey, std::vector<Transaction> &&list,
               const Callback<std::vector<Transaction>> &done);
  void trySilentDecrypt(const QByteArray &publicKey, std::vector<Transaction> &&list,
                        const Callback<std::vector<Transaction>> &done);

  void getWalletOwner(const QString &rootTokenContract, const QString &walletAddress, const Callback<QString> &done);
  void getWalletOwners(const QString &rootTokenContract, const QSet<QString> &addresses,
                       const Fn<void(std::map<QString, QString> &&)> &done);

  // Internal API.
  void requestState(const QString &address, const Callback<AccountState> &done);
  void requestTransactions(const QString &address, const TransactionId &lastId,
                           const Callback<TransactionsSlice> &done);
  void requestTokenStates(const CurrencyMap<TokenStateValue> &previousStates,
                          const Callback<CurrencyMap<TokenStateValue>> &done) const;
  void requestDePoolParticipantInfo(const QByteArray &publicKey, const DePoolStatesMap &previousStates,
                                    const Callback<DePoolStatesMap> &done) const;

 private:
  struct ViewersPassword {
    QByteArray bytes;
    int generation = 1;
    crl::time expires = 0;
  };
  void setWalletList(const details::WalletList &list);
  [[nodiscard]] details::TLinputKey prepareInputKey(const QByteArray &publicKey, const QByteArray &password) const;
  [[nodiscard]] Fn<void(Update)> generateUpdatesCallback();
  void checkLocalTime(details::BlockchainTime time);
  void notifyPasswordGood(const QByteArray &publicKey, int generation);
  void checkPasswordsExpiration();
  [[nodiscard]] QString getDefaultAddress(const QByteArray &publicKey, int revision) const;

  void handleInputKeyError(const QByteArray &publicKey, int generation, const details::TLerror &error, Callback<> done);

  auto makeSendCallback(const Callback<> &done) -> std::function<void(int64)>;
  auto makeEstimateFeesCallback(const Callback<TransactionCheckResult> &done) -> std::function<void(int64)>;
  void checkTransactionFees(const QString &sender, const QString &recipient,
                            const tl::boxed<Ton::details::TLmsg_data> &body, int64 realAmount, int timeout,
                            bool allowSendToUninited, const Callback<TransactionCheckResult> &done);
  void sendMessage(const QByteArray &publicKey, const QByteArray &password, const QString &sender,
                   const QString &recipient, const tl::boxed<Ton::details::TLmsg_data> &body, int64 realAmount,
                   int timeout, bool allowSendToUninited, const Callback<PendingTransaction> &ready,
                   const Callback<> &done);
  void sendMessage(const QByteArray &publicKey, const QByteArray &password, const QString &sender,
                   const QString &recipient, const tl::boxed<Ton::details::TLmsg_data> &body, int64 realAmount,
                   int timeout, bool allowSendToUninited, const QString &comment, bool sendUnencryptedText,
                   const Callback<PendingTransaction> &ready, const Callback<> &done);

  std::optional<ConfigInfo> _configInfo;
  rpl::event_stream<Update> _updates;
  SyncState _lastSyncStateUpdate;
  bool _switchedToMain = false;

  const std::unique_ptr<details::External> _external;
  const std::unique_ptr<details::AccountViewers> _accountViewers;
  const std::unique_ptr<details::WalletList> _list;
  std::unique_ptr<details::WebLoader> _webLoader;
  std::unique_ptr<details::KeyCreator> _keyCreator;
  std::unique_ptr<details::KeyDestroyer> _keyDestroyer;
  std::unique_ptr<details::PasswordChanger> _passwordChanger;
  std::unique_ptr<details::LocalTimeSyncer> _localTimeSyncer;

  base::flat_map<QByteArray, ViewersPassword> _viewersPasswords;
  base::flat_map<QByteArray, std::vector<Callback<>>> _viewersPasswordsWaiters;
  base::Timer _viewersPasswordsExpireTimer;

  QString _gateUrl;

  rpl::lifetime _lifetime;
};

}  // namespace Ton
