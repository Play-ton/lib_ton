// This file is part of Desktop App Toolkit,
// a set of libraries for developing nice desktop applications.
//
// For license and copyright information please follow this link:
// https://github.com/desktop-app/legal/blob/master/LEGAL
//
#pragma once

#include "ton/ton_result.h"

namespace Storage::Cache {
class Database;
struct Error;
}  // namespace Storage::Cache

namespace Ton {
struct TransactionId;
struct AccountState;
struct Message;
struct Transaction;
struct TransactionsSlice;
struct PendingTransaction;
struct WalletState;
struct Settings;
}  // namespace Ton

namespace Ton::details {

class RequestSender;

struct WalletList {
  struct Entry {
    QByteArray publicKey;
    QByteArray secret;
    QString address;
  };
  std::vector<Entry> entries;
};

struct TokenOwnersCache {
  std::map<QString, QString> entries;
};

[[nodiscard]] std::optional<Error> ErrorFromStorage(const Storage::Cache::Error &error);

void DeletePublicKey(not_null<RequestSender *> lib, const QByteArray &publicKey, const QByteArray &secret,
                     Callback<> done);

void SaveWalletList(not_null<Storage::Cache::Database *> db, const WalletList &list, bool useTestNetwork,
                    Callback<> done);
void LoadWalletList(not_null<Storage::Cache::Database *> db, bool useTestNetwork, Fn<void(WalletList &&)> done);

void SaveTokenOwnersCache(not_null<Storage::Cache::Database *> db, bool useTestNetwork,
                          const QString &rootContractAddress, const TokenOwnersCache &owners, const Callback<>& done);
void LoadTokenOwnersCache(not_null<Storage::Cache::Database *> db, bool useTestNetwork,
                          const QString &rootContractAddress, const Fn<void(TokenOwnersCache &&)>& done);

void SaveWalletState(not_null<Storage::Cache::Database *> db, const WalletState &state, const Callback<>& done);
void LoadWalletState(not_null<Storage::Cache::Database *> db, const QString &address, const Fn<void(WalletState &&)>& done);

void SaveSettings(not_null<Storage::Cache::Database *> db, const Settings &settings, const Callback<>& done);
void LoadSettings(not_null<Storage::Cache::Database *> db, const Fn<void(Settings &&)>& done);

}  // namespace Ton::details
