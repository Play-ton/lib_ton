// This file is part of Desktop App Toolkit,
// a set of libraries for developing nice desktop applications.
//
// For license and copyright information please follow this link:
// https://github.com/desktop-app/legal/blob/master/LEGAL
//
#pragma once

#include "ton/details/ton_request_sender.h"
#include "ton/ton_result.h"
#include "ton/ton_settings.h"
#include "storage/storage_databases.h"
#include "base/bytes.h"
#include "base/weak_ptr.h"

namespace Storage::Cache {
class Database;
}  // namespace Storage::Cache

namespace Ton {
struct Update;
struct ConfigInfo;
}  // namespace Ton

namespace Ton::details {

class RequestSender;
struct WalletList;

class External final : public base::has_weak_ptr {
 public:
  External(const QString &path, Fn<void(Update)> &&updateCallback);

  void open(const QByteArray &globalPassword, const Settings &defaultSettings, Callback<WalletList> done);
  void start(Callback<ConfigInfo> done);

  [[nodiscard]] const Settings &settings() const;
  void updateSettings(const Settings &settings, Callback<ConfigInfo> done);
  void switchNetwork(Callback<ConfigInfo> done);

  [[nodiscard]] RequestSender &lib();
  [[nodiscard]] Storage::Cache::Database &db();

  static void EnableLogging(bool enabled, const QString &basePath);
  static void LogMessage(const QString &message);

 private:
  enum class State {
    Initial,
    Opening,
    Opened,
  };

  [[nodiscard]] Result<> loadSalt();
  [[nodiscard]] Result<> writeNewSalt();
  [[nodiscard]] Fn<void(const TLUpdate &)> generateUpdateCallback() const;
  void openDatabase(const QByteArray &globalPassword, Callback<Settings> done);
  void startLibrary(Callback<> done);
  void resetNetwork();
  void applyLocalSettings(const Settings &localSettings);

  const QString _basePath;
  const Fn<void(Update)> _updateCallback;
  Settings _settings;
  RequestSender _lib;
  Storage::DatabasePointer _db;
  ConfigUpgrade _configUpgrade = ConfigUpgrade::None;

  State _state = State::Initial;
  bytes::vector _salt;

  int _failedRequestsSinceSetConfig = 0;
  rpl::lifetime _lifetime;
};

}  // namespace Ton::details
