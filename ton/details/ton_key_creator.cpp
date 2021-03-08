// This file is part of Desktop App Toolkit,
// a set of libraries for developing nice desktop applications.
//
// For license and copyright information please follow this link:
// https://github.com/desktop-app/legal/blob/master/LEGAL
//
#include "ton/details/ton_key_creator.h"

#include "ton/details/ton_request_sender.h"
#include "ton/details/ton_parse_state.h"
#include "ton/details/ton_external.h"
#include "ton/details/ton_storage.h"
#include "base/openssl_help.h"

namespace Ton::details {
namespace {

constexpr auto kLocalPasswordSize = size_type(32);
constexpr auto kRestrictedWalletRevision = 1;

[[nodiscard]] QByteArray GenerateLocalPassword() {
  auto result = QByteArray(kLocalPasswordSize, Qt::Uninitialized);
  bytes::set_random(bytes::make_detached_span(result));
  return result;
}

}  // namespace

KeyCreator::KeyCreator(not_null<RequestSender *> lib, not_null<Storage::Cache::Database *> db,
                       const Fn<void(Result<std::vector<QString>>)> &done)
    : _lib(lib), _db(db), _password(GenerateLocalPassword()) {
  _lib->request(TLCreateNewKey(TLsecureString{_password}, TLsecureString(), TLsecureString()))
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

KeyCreator::KeyCreator(not_null<RequestSender *> lib, not_null<Storage::Cache::Database *> db,
                       const std::vector<QString> &words, const Fn<void(Result<>)> &done)
    : _lib(lib), _db(db), _password(GenerateLocalPassword()) {
  auto list = QVector<TLsecureString>();
  list.reserve(words.size());
  for (const auto &word : words) {
    list.push_back(TLsecureString{word.toUtf8()});
  }
  _lib->request(
          TLImportKey(TLsecureString{_password}, TLsecureString(), tl_exportedKey(tl_vector<TLsecureString>(list))))
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

void KeyCreator::exportWords(const Fn<void(Result<std::vector<QString>>)> &done) {
  Expects(_state == State::Creating);
  Expects(!_key.isEmpty());
  Expects(!_secret.isEmpty());

  _lib->request(
          TLExportKey(tl_inputKeyRegular(tl_key(tl_string(_key), TLsecureBytes{_secret}), TLsecureBytes{_password})))
      .done(crl::guard(this,
                       [=](const TLExportedKey &result) {
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

QByteArray KeyCreator::key() const {
  Expects(!_key.isEmpty());

  return _key;
}

void KeyCreator::queryWalletAddress(const QByteArray &restrictedInitPublicKey, const Callback<QString> &done) {
  Expects(!_key.isEmpty());

  _lib->request(TLGuessAccount(tl_string(_key), tl_string(restrictedInitPublicKey)))
      .done([=](const TLAccountRevisionList &result) {
        result.match([&](const TLDaccountRevisionList &data) {
          const auto list = data.vrevisions().v;
          if (list.isEmpty()) {
            InvokeCallback(done, QString());
            return;
          }
          list.front().match([&](const TLDfullAccountState &data) {
            const auto address = data.vaddress().match(
                [&](const TLDaccountAddress &data) { return tl::utf16(data.vaccount_address()); });
            InvokeCallback(done, address);
          });
        });
      })
      .fail([=](const TLError &error) { InvokeCallback(done, ErrorFromLib(error)); })
      .send();
}

void KeyCreator::save(const QByteArray &password, const WalletList &existing, const QString &address,
                      bool useTestNetwork, const Callback<WalletList::Entry> &done) {
  _address = address;
  if (_password != password) {
    changePassword(password, [=](Result<> result) {
      _state = State::Created;
      if (!result) {
        InvokeCallback(done, result.error());
        return;
      }
      saveToDatabase(existing, useTestNetwork, done);
    });
  } else {
    saveToDatabase(existing, useTestNetwork, std::move(done));
  }
}

void KeyCreator::saveToDatabase(WalletList existing, bool useTestNetwork, const Callback<WalletList::Entry> &done) {
  Expects(_state == State::Created);
  Expects(!_key.isEmpty());
  Expects(!_secret.isEmpty());

  _state = State::Saving;
  const auto added = WalletList::Entry{
      .publicKey = _key,
      .secret = _secret,
      .address = _address,
  };
  existing.entries.push_back(added);
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

void KeyCreator::changePassword(const QByteArray &password, Callback<> done) {
  Expects(_state == State::Created);
  Expects(!_key.isEmpty());
  Expects(!_secret.isEmpty());
  Expects(_password != password);

  _state = State::ChangingPassword;
  _lib->request(TLChangeLocalPassword(
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

}  // namespace Ton::details
