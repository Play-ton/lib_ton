#include "ton_ftabi_password_changer.h"

namespace Ton::details {

FtabiPasswordChanger::FtabiPasswordChanger(not_null<RequestSender *> lib, not_null<Storage::Cache::Database *> db,
                                           QByteArray oldPassword, QByteArray newPassword, WalletList existing,
                                           const QByteArray &publicKey, bool useTestNetwork,
                                           const Callback<QByteArray> &done)
    : _lib(lib)
    , _db(db)
    , _oldPassword(std::move(oldPassword))
    , _newPassword(std::move(newPassword))
    , _done(std::move(done))
    , _useTestNetwork(useTestNetwork)
    , _list(std::move(existing)) {
  const auto it = std::find_if(_list.ftabiEntries.begin(), _list.ftabiEntries.end(),
                               [&](const auto &entry) { return entry.publicKey == publicKey; });
  if (it == _list.ftabiEntries.end()) {
    InvokeCallback(done, Error{Error::Type::TonLib, "specified ftabi key was not found"});
  }

  _index = it - _list.ftabiEntries.begin();

  _lib->request(TLftabi_ChangeLocalPassword(  //
                    tl_inputKeyRegular(tl_key(tl_string(_list.ftabiEntries[_index].publicKey),
                                              TLsecureBytes{_list.ftabiEntries[_index].secret}),
                                       TLsecureBytes{_oldPassword}),
                    TLsecureBytes{_newPassword}))
      .done([=](const TLKey &result) { saved(result.match([&](const TLDkey &data) { return data.vsecret().v; })); })
      .fail([=](const TLError &error) { rollback(ErrorFromLib(error)); })
      .send();
}

void FtabiPasswordChanger::saved(const QByteArray &newSecret) {
  _newSecret = newSecret;
  auto copy = _list;
  copy.ftabiEntries[_index].secret = newSecret;
  const auto saved = [=](Result<> result) {
    if (!result) {
      rollback(result.error());
    } else {
      rollforward();
    }
  };
  SaveWalletList(_db, copy, _useTestNetwork, crl::guard(this, saved));
}

void FtabiPasswordChanger::rollback(const Error &error) {
  Expects(_index < _list.ftabiEntries.size());

  const auto &oldEntry = _list.ftabiEntries[_index];
  DeletePublicKey(_lib, oldEntry.publicKey, _newSecret,
                  crl::guard(this, [=](const Result<> &) { InvokeCallback(_done, error); }));
}

void FtabiPasswordChanger::rollforward() {
  const auto &oldEntry = _list.ftabiEntries[_index];
  DeletePublicKey(_lib, oldEntry.publicKey, oldEntry.secret,
                  crl::guard(this, [=](const Result<> &) { InvokeCallback(_done, _newSecret); }));
}

}  // namespace Ton::details
