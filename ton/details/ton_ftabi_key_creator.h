#pragma once

#include "ton/details/ton_external.h"
#include "ton/details/ton_storage.h"
#include "ton/ton_state.h"

namespace Storage::Cache {
class Database;
}  // namespace Storage::Cache

namespace Ton::details {

class RequestSender;

class FtabiKeyCreator final : public base::has_weak_ptr {
 public:
  FtabiKeyCreator(not_null<RequestSender *> lib, not_null<Storage::Cache::Database *> db, const QString &derivationPath,
                  const Fn<void(Result<std::vector<QString>>)> &done);
  FtabiKeyCreator(not_null<RequestSender *> lib, not_null<Storage::Cache::Database *> db, const QString &derivationPath,
                  const std::vector<QString> &words, const Fn<void(Result<>)> &done);

  [[nodiscard]] QByteArray key() const;
  void save(const QByteArray &password, const WalletList &existing, bool useTestNetwork,
            const Callback<WalletList::FtabiEntry> &done);

 private:
  enum class State {
    Creating,
    Created,
    ChangingPassword,
    Saving,
  };

  void exportWords(const Fn<void(Result<std::vector<QString>>)> &done);
  void changePassword(const QByteArray &password, Callback<> done);
  void saveToDatabase(WalletList existing, bool useTestNetwork, Callback<WalletList::FtabiEntry> done);

  const not_null<RequestSender *> _lib;
  const not_null<Storage::Cache::Database *> _db;

  State _state = State::Creating;
  QByteArray _key;
  QByteArray _secret;
  QByteArray _password;
};

}  // namespace Ton::details
