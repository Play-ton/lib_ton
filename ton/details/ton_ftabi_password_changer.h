#pragma once

#include "base/weak_ptr.h"
#include "ton/ton_result.h"
#include "ton/details/ton_external.h"
#include "ton/details/ton_storage.h"

namespace Storage::Cache {
class Database;
}  // namespace Storage::Cache

namespace Ton {
struct Error;
}  // namespace Ton

namespace Ton::details {

class RequestSender;
struct WalletList;

class FtabiPasswordChanger final : public base::has_weak_ptr {
 public:
  FtabiPasswordChanger(not_null<RequestSender *> lib, not_null<Storage::Cache::Database *> db, QByteArray oldPassword,
                       QByteArray newPassword, WalletList existing, const QByteArray &publicKey, bool useTestNetwork,
                       const Callback<QByteArray> &done);

 private:
  void saved(const QByteArray &newSecret);
  void rollback(const Error &error);
  void rollforward();

  const not_null<RequestSender *> _lib;
  const not_null<Storage::Cache::Database *> _db;
  const QByteArray _oldPassword;
  const QByteArray _newPassword;
  const Callback<QByteArray> _done;
  const bool _useTestNetwork = false;
  WalletList _list;
  int _index;
  QByteArray _newSecret;
};

}  // namespace Ton::details
