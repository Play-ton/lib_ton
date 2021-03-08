#include "ton_ftabi_key_creator.h"

#include "ton/details/ton_parse_state.h"

namespace Ton::details {
namespace {

constexpr auto kLocalPasswordSize = size_type(32);

[[nodiscard]] QByteArray GenerateLocalPassword() {
  auto result = QByteArray(kLocalPasswordSize, Qt::Uninitialized);
  bytes::set_random(bytes::make_detached_span(result));
  return result;
}

}  // namespace

FtabiKeyCreator::FtabiKeyCreator(not_null<RequestSender *> lib, not_null<Storage::Cache::Database *> db,
                                 const QString &derivationPath, const Fn<void(Result<std::vector<QString>>)> &done)
    : _lib(lib), _db(db), _password(GenerateLocalPassword()) {
  _lib->request(TLftabi_CreateNewKey(TLsecureString{_password}, tl_string(derivationPath)))
      .done(crl::guard(this,
                       [=](const TLKey &key) {
                         key.match([&](const TLDkey &data) {
                           _key = data.vpublic_key().v;
                           _secret = data.vsecret().v;
                         });
                         exportWords(done);
                       }))
      .fail(crl::guard(this, [=](const TLError &error) { InvokeCallback(done, ErrorFromLib(error)); }))
      .send();
}

FtabiKeyCreator::FtabiKeyCreator(not_null<RequestSender *> lib, not_null<Storage::Cache::Database *> db,
                                 const QString &derivationPath, const std::vector<QString> &words,
                                 const Fn<void(Result<>)> &done)
    : _lib(lib), _db(db), _password(GenerateLocalPassword()) {
  auto list = QVector<TLsecureString>();
  list.reserve(words.size());
  for (const auto &word : words) {
    list.push_back(TLsecureString{word.toUtf8()});
  }
  _lib->request(TLftabi_ImportKey(TLsecureString{_password},
                                  tl_ftabi_exportedKey(tl_vector<TLsecureString>(list), tl_string(derivationPath))))
      .done(crl::guard(this,
                       [=](const TLKey &key) {
                         _state = State::Created;
                         key.match([&](const TLDkey &data) {
                           _key = data.vpublic_key().v;
                           _secret = data.vsecret().v;
                         });
                         InvokeCallback(done);
                       }))
      .fail(crl::guard(this, [=](const TLError &error) { InvokeCallback(done, ErrorFromLib(error)); }))
      .send();
}

QByteArray FtabiKeyCreator::key() const {
  Expects(!_key.isEmpty());

  return _key;
}

void FtabiKeyCreator::save(const QByteArray &password, const WalletList &existing, bool useTestNetwork,
                           const Callback<WalletList::FtabiEntry> &done) {
  if (_password != password) {
    changePassword(password, [=](const Result<> &result) {
      _state = State::Created;
      if (!result) {
        InvokeCallback(done, result.error());
        return;
      }
      saveToDatabase(existing, useTestNetwork, done);
    });
  } else {
    saveToDatabase(existing, useTestNetwork, done);
  }
}

void FtabiKeyCreator::changePassword(const QByteArray &password, Callback<> done) {
  Expects(_state == State::Created);
  Expects(!_key.isEmpty());
  Expects(!_secret.isEmpty());
  Expects(_password != password);

  _state = State::ChangingPassword;
  _lib->request(TLftabi_ChangeLocalPassword(
                    tl_inputKeyRegular(tl_key(tl_string(_key), TLsecureBytes{_secret}), TLsecureBytes{_password}),
                    TLsecureBytes{password}))
      .done(crl::guard(this,
                       [=](const TLKey &result) {
                         DeletePublicKey(_lib, _key, _secret, crl::guard(this, [=](const Result<> &) {
                                           result.match([&](const TLDkey &data) {
                                             _password = password;
                                             _secret = data.vsecret().v;
                                             InvokeCallback(done);
                                           });
                                         }));
                       }))
      .fail(crl::guard(this, [=](const TLError &error) { InvokeCallback(done, ErrorFromLib(error)); }))
      .send();
}

void FtabiKeyCreator::exportWords(const Fn<void(Result<std::vector<QString>>)> &done) {
  Expects(_state == State::Creating);
  Expects(!_key.isEmpty());
  Expects(!_secret.isEmpty());

  _lib->request(TLftabi_ExportKey(
                    tl_inputKeyRegular(tl_key(tl_string(_key), TLsecureBytes{_secret}), TLsecureBytes{_password})))
      .done(crl::guard(this,
                       [=](const TLftabi_ExportedKey &result) {
                         _state = State::Created;
                         InvokeCallback(done, Parse(result));
                       }))
      .fail(crl::guard(this,
                       [=](const TLError &error) {
                         DeletePublicKey(_lib, _key, _secret, crl::guard(this, [=](const Result<> &) {
                                           InvokeCallback(done, ErrorFromLib(error));
                                         }));
                       }))
      .send();
}

void FtabiKeyCreator::saveToDatabase(WalletList existing, bool useTestNetwork, Callback<WalletList::FtabiEntry> done) {
  Expects(_state == State::Created);
  Expects(!_key.isEmpty());
  Expects(!_secret.isEmpty());

  _state = State::Saving;
  const auto added = WalletList::FtabiEntry{
      .publicKey = _key,
      .secret = _secret,
  };
  existing.ftabiEntries.push_back(added);
  const auto saved = [=](Result<> result) {
    if (!result) {
      _state = State::Created;
      InvokeCallback(done, result.error());
    } else {
      InvokeCallback(done, added);
    }
  };
  SaveWalletList(_db, existing, useTestNetwork, crl::guard(this, saved));
}

}  // namespace Ton::details
