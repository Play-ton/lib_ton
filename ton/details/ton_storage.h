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
struct IgnoredAssetsList;
}  // namespace Ton

namespace Ton::details {

class RequestSender;

struct WalletList {
  struct Entry {
    QByteArray publicKey;
    QByteArray secret;
    QString address;
  };

  struct FtabiEntry {
    QString name;
    QByteArray publicKey;
    QByteArray secret;
  };

  std::vector<Entry> entries;
  std::vector<FtabiEntry> ftabiEntries;
};

struct TokenOwnersCache {
  std::map<QString, QString> entries;
};

struct KnownTokenContracts {
  std::vector<QString> addresses;
};

[[nodiscard]] std::optional<Error> ErrorFromStorage(const Storage::Cache::Error &error);

void DeletePublicKey(not_null<RequestSender *> lib, const QByteArray &publicKey, const QByteArray &secret,
                     const Callback<> &done);

void SaveWalletList(not_null<Storage::Cache::Database *> db, const WalletList &list, bool useTestNetwork,
                    const Callback<> &done);
void LoadWalletList(not_null<Storage::Cache::Database *> db, bool useTestNetwork, const Fn<void(WalletList &&)> &done);

void SaveIgnoredAssetsList(not_null<Storage::Cache::Database *> db, bool useTestNetwork,
                           const IgnoredAssetsList &ignoredAssets, const Callback<> &done);
void LoadIgnoredAssetsList(not_null<Storage::Cache::Database *> db, bool useTestNetwork,
                           const Fn<void(IgnoredAssetsList &&)> &done);

void SaveTokenOwnersCache(not_null<Storage::Cache::Database *> db, bool useTestNetwork,
                          const QString &rootContractAddress, const TokenOwnersCache &owners, const Callback<> &done);
void LoadTokenOwnersCache(not_null<Storage::Cache::Database *> db, bool useTestNetwork,
                          const QString &rootContractAddress, const Fn<void(TokenOwnersCache &&)> &done);

void SaveKnownTokenContracts(not_null<Storage::Cache::Database *> db, bool useTestNetwork,
                             const KnownTokenContracts &knownContracts, const Callback<> &done);
void LoadKnownTokenContracts(not_null<Storage::Cache::Database *> db, bool useTestNetwork,
                             const Fn<void(KnownTokenContracts &&)> &done);

void SaveWalletState(not_null<Storage::Cache::Database *> db, const WalletState &state, Callback<> &&done);
void LoadWalletState(not_null<Storage::Cache::Database *> db, const QString &address,
                     const Fn<void(WalletState &&)> &done);

void SaveSettings(not_null<Storage::Cache::Database *> db, const Settings &settings, const Callback<> &done);
void LoadSettings(not_null<Storage::Cache::Database *> db, const Fn<void(Settings &&)> &done);

}  // namespace Ton::details
