// This file is part of Desktop App Toolkit,
// a set of libraries for developing nice desktop applications.
//
// For license and copyright information please follow this link:
// https://github.com/desktop-app/legal/blob/master/LEGAL
//
#include "ton/ton_wallet.h"

#include "ton/details/ton_account_viewers.h"
#include "ton/details/ton_request_sender.h"
#include "ton/details/ton_ftabi_key_creator.h"
#include "ton/details/ton_ftabi_password_changer.h"
#include "ton/details/ton_key_creator.h"
#include "ton/details/ton_key_destroyer.h"
#include "ton/details/ton_password_changer.h"
#include "ton/details/ton_external.h"
#include "ton/details/ton_parse_state.h"
#include "ton/details/ton_web_loader.h"
#include "ton/details/ton_abi.h"
#include "ton/ton_settings.h"
#include "ton/ton_state.h"
#include "ton/ton_account_viewer.h"
#include "storage/cache/storage_cache_database.h"
#include "storage/storage_encryption.h"
#include "base/openssl_help.h"

#include <crl/crl_async.h>
#include <crl/crl_on_main.h>
#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include <QtCore/QByteArray>
#include <QtGui/QDesktopServices>
#include <memory>
#include <utility>
#include <iostream>
#include <shared_mutex>

namespace Ton {
namespace {

using namespace details;

constexpr auto kViewersPasswordExpires = 15 * 60 * crl::time(1000);
constexpr auto kDefaultSmcRevision = 0;
constexpr auto kLegacySmcRevision = 1;
constexpr auto kDefaultWorkchainId = 0;
constexpr auto kDefaultMessageFlags = 3;

[[nodiscard]] TLError GenerateFakeIncorrectPasswordError() {
  return tl_error(tl_int32(0), tl_string("KEY_DECRYPT"));
}

[[nodiscard]] TLError GenerateInvalidAbiError() {
  return tl_error(tl_int32(500), tl_string("INVALID_ABI"));
}

[[nodiscard]] TLError GenerateVmError(int32 exitCode) {
  return tl_error(tl_int32(500), tl_string(QString{"VM terminated with exit code: %1"}.arg(exitCode)));
}

[[nodiscard]] TLError GenerateVmError(const TLint32 &exitCode) {
  return GenerateVmError(exitCode.v);
}

std::optional<int32> GuessDePoolVersion(const QByteArray &codeHash) {
  static const std::vector<QByteArray> codeHashes = {
      QByteArray::fromHex("b4ad6c42427a12a65d9a0bffb0c2730dd9cdf830a086d94636dab7784e13eb38"),
      QByteArray::fromHex("a46c6872712ec49e481a7f3fc1f42469d8bd6ef3fae906aa5b9927e5a3fb3b6b"),
      QByteArray::fromHex("14e20e304f53e6da152eb95fffc993dbd28245a775d847eed043f7c78a503885"),
  };

  for (int32 i = 0; i < codeHashes.size(); ++i) {
    if (codeHashes[i] == codeHash) {
      return i + 1;
    }
  }
  return std::nullopt;
}

std::optional<MultisigVersion> GuessMultisigVersion(const QByteArray &codeHash) {
  static const std::map<QByteArray, MultisigVersion> codeHashes = {
      {QByteArray::fromHex("80d6c47c4a25543c9b397b71716f3fae1e2c5d247174c52e2c19bd896442b105"),  //
       MultisigVersion::SafeMultisig},
      {QByteArray::fromHex("7d0996943406f7d62a4ff291b1228bf06ebd3e048b58436c5b70fb77ff8b4bf2"),  //
       MultisigVersion::SafeMultisig24h},
      {QByteArray::fromHex("e2b60b6b602c10ced7ea8ede4bdf96342c97570a3798066f3fb50a4b2b27a208"),  //
       MultisigVersion::SetcodeMultisig},
      {QByteArray::fromHex("207dc560c5956de1a2c1479356f8f3ee70a59767db2bf4788b1d61ad42cdad82"),  //
       MultisigVersion::Surf},
  };
  const auto it = codeHashes.find(codeHash);
  if (it == codeHashes.end()) {
    return std::nullopt;
  }
  return it->second;
}

}  // namespace

namespace details {

struct UnpackedAddress {
  TLinitialAccountState state;
  int32 revision = 0;
  int32 workchainId = 0;
};

}  // namespace details

Wallet::Wallet(const QString &path)
    : _external(std::make_unique<External>(path, generateUpdatesCallback()))
    , _accountViewers(std::make_unique<AccountViewers>(this, &_external->lib(), &_external->db()))
    , _list(std::make_unique<WalletList>())
    , _viewersPasswordsExpireTimer([=] { checkPasswordsExpiration(); }) {
  crl::async([] {
    // Init random, because it is slow.
    static_cast<void>(openssl::RandomValue<uint8>());
  });
  _accountViewers->blockchainTime() |
      rpl::start_with_next([=](BlockchainTime time) { checkLocalTime(time); }, _lifetime);

  _gateUrl = "https://tonbridge.io/";
}

Wallet::~Wallet() = default;

void Wallet::EnableLogging(bool enabled, const QString &basePath) {
  External::EnableLogging(enabled, basePath);
}

void Wallet::LogMessage(const QString &message) {
  return External::LogMessage(message);
}

bool Wallet::CheckAddress(const QString &address) {
  return RequestSender::Execute(TLUnpackAccountAddress(tl_string(address))) ? true : false;
}

QString Wallet::ConvertIntoRaw(const QString &address) {
  const auto result = RequestSender::Execute(TLUnpackAccountAddress(tl_string(address)));
  Expects(result.has_value());

  const auto &unpacked = result->c_unpackedAccountAddress();
  const auto workchain = unpacked.vworkchain_id().v;
  const auto addr = QString::fromLocal8Bit(unpacked.vaddr().v.toHex());

  return QString{"%1:%2"}.arg(workchain).arg(addr);
}

QString Wallet::ConvertIntoPacked(const QString &address) {
  const auto result = RequestSender::Execute(TLConvertIntoPacked(tl_string(address), tl_boolTrue()));
  Expects(result.has_value());
  return result.value().c_accountAddress().vaccount_address().v;
}

QByteArray Wallet::PackPublicKey(const QByteArray &publicKey) {
  const auto result = RequestSender::Execute(TLftabi_PackPublicKey(tl_string(publicKey)));
  Expects(result.has_value());
  return result.value().c_ftabi_packedPublicKey().vpublic_key().v;
}

QByteArray Wallet::UnpackPublicKey(const QByteArray &publicKey) {
  const auto result = RequestSender::Execute(TLftabi_UnpackPublicKey(tl_string(publicKey)));
  Expects(result.has_value());
  return result.value().c_ftabi_unpackedPublicKey().vpublic_key().v;
}

QByteArray Wallet::ExtractContractPublicKey(const QByteArray &data) {
  const auto request = RequestSender::Execute(TLftabi_UnpackPublicKey());
}

base::flat_set<QString> Wallet::GetValidWords() {
  const auto result = RequestSender::Execute(TLGetBip39Hints(tl_string()));
  Assert(result);

  return result->match([&](const TLDbip39Hints &data) {
    auto &&words = ranges::views::all(data.vwords().v) |
                   ranges::views::transform([](const TLstring &word) { return QString::fromUtf8(word.v); });
    return base::flat_set<QString>{words.begin(), words.end()};
  });
}

bool Wallet::IsIncorrectPasswordError(const Error &error) {
  return error.details.startsWith(qstr("KEY_DECRYPT"));
}

void Wallet::open(const QByteArray &globalPassword, const Settings &defaultSettings, const Callback<> &done) {
  auto opened = [=](Result<WalletList> result) {
    if (!result) {
      return InvokeCallback(done, result.error());
    }
    setWalletList(*result);
    if (_switchedToMain) {
      auto copy = settings();
      copy.useTestNetwork = false;
      updateSettings(copy, done);
    } else {
      _external->lib().request(TLSync()).send();
      InvokeCallback(done);
    }
  };
  _external->open(globalPassword, defaultSettings, std::move(opened));
}

void Wallet::start(const Callback<> &done) {
  _external->start([=](Result<ConfigInfo> result) {
    if (!result) {
      return InvokeCallback(done, result.error());
    }
    _configInfo = *result;
    InvokeCallback(done);
  });
}

QString Wallet::getUsedAddress(const QByteArray &publicKey) const {
  const auto i = ranges::find(_list->entries, publicKey, &WalletList::Entry::publicKey);
  Assert(i != end(_list->entries));
  return i->address.isEmpty() ? getDefaultAddress(publicKey, kLegacySmcRevision) : i->address;
}

QString Wallet::getDefaultAddress(const QByteArray &publicKey, int revision) const {
  Expects(_configInfo.has_value());

  return RequestSender::Execute(
             TLGetAccountAddress(tl_wallet_v3_initialAccountState(
                                     tl_string(publicKey), tl_int64(_configInfo->walletId + kDefaultWorkchainId)),
                                 tl_int32(revision), tl_int32(kDefaultWorkchainId)))
      .value_or(tl_accountAddress(tl_string()))
      .match([&](const TLDaccountAddress &data) { return tl::utf16(data.vaccount_address()); });
}

const Settings &Wallet::settings() const {
  return _external->settings();
}

void Wallet::updateSettings(Settings settings, const Callback<> &done) {
  const auto &was = _external->settings();
  const auto detach = (was.net().blockchainName != settings.net().blockchainName);
  const auto change = (was.useTestNetwork != settings.useTestNetwork);

  const auto finish = [=](Result<ConfigInfo> result) {
    if (!result) {
      return InvokeCallback(done, result.error());
    }
    Expects(!_configInfo || (_configInfo->walletId == result->walletId) || detach || change);
    _configInfo = *result;
    InvokeCallback(done);
  };
  if (!change) {
    _external->updateSettings(settings, finish);
    return;
  }
  // First just save the new settings.
  settings.useTestNetwork = was.useTestNetwork;
  _external->updateSettings(settings, [=](Result<ConfigInfo> result) {
    if (!result) {
      return InvokeCallback(done, result.error());
    }
    // Then logout and switch the network.
    deleteAllKeys([=](Result<> result) {
      if (!result) {
        return InvokeCallback(done, result.error());
      }
      _external->switchNetwork(finish);
    });
  });
}

void Wallet::checkConfig(const QByteArray &config, const Callback<> &done) {
  // We want to check only validity of config,
  // not validity in one specific blockchain_name.
  // So we pass an empty blockchain name.
  _external->lib()
      .request(
          TLoptions_ValidateConfig(tl_config(tl_string(config), tl_string(QString()), tl_from(false), tl_from(false))))
      .done([=] { InvokeCallback(done); })
      .fail([=](const TLError &error) { InvokeCallback(done, ErrorFromLib(error)); })
      .send();
}

void Wallet::sync() {
  _external->lib().request(TLSync()).send();
}

rpl::producer<Update> Wallet::updates() const {
  return _updates.events();
}

std::vector<QByteArray> Wallet::publicKeys() const {
  return _list->entries | ranges::views::transform(&WalletList::Entry::publicKey) | ranges::to_vector;
}

std::vector<FtabiKey> Wallet::ftabiKeys() const {
  return _list->ftabiEntries  //
         | ranges::views::transform([](const WalletList::FtabiEntry &entry) {
             return FtabiKey{
                 .name = entry.name,
                 .publicKey = entry.publicKey,
             };
           })  //
         | ranges::to_vector;
}

void Wallet::createKey(const Callback<std::vector<QString>> &done) {
  Expects(_originalKeyCreator == nullptr);
  Expects(_keyDestroyer == nullptr);
  Expects(_passwordChanger == nullptr);

  auto created = [=](const Result<std::vector<QString>> &result) {
    const auto destroyed = result ? std::unique_ptr<KeyCreator>() : base::take(_originalKeyCreator);
    InvokeCallback(done, result);
  };
  _originalKeyCreator = std::make_unique<KeyCreator>(&_external->lib(), &_external->db(), created);
}

void Wallet::createFtabiKey(const QString &name, const QString &derivationPath,
                            const Callback<std::vector<QString>> &done) {
  auto created = [=](const Result<std::vector<QString>> &result) {
    const auto destroyed = result ? std::unique_ptr<FtabiKeyCreator>() : base::take(_ftabiKeyCreator);
    InvokeCallback(done, result);
  };
  _ftabiKeyCreator =
      std::make_unique<FtabiKeyCreator>(&_external->lib(), &_external->db(), name, derivationPath, created);
}

void Wallet::importKey(const std::vector<QString> &words, const Callback<> &done) {
  Expects(_originalKeyCreator == nullptr);
  Expects(_keyDestroyer == nullptr);
  Expects(_passwordChanger == nullptr);

  auto created = [=](Result<> result) {
    const auto destroyed = result ? std::unique_ptr<KeyCreator>() : base::take(_originalKeyCreator);
    InvokeCallback(done, result);
  };
  _originalKeyCreator = std::make_unique<KeyCreator>(&_external->lib(), &_external->db(), words, std::move(created));
}

void Wallet::importFtabiKey(const QString &name, const QString &derivationPath, const std::vector<QString> &words,
                            const Callback<> &done) {
  auto created = [=](Result<> result) {
    const auto destroyed = result ? std::unique_ptr<FtabiKeyCreator>() : base::take(_ftabiKeyCreator);
    InvokeCallback(done, result);
  };
  _ftabiKeyCreator = std::make_unique<FtabiKeyCreator>(&_external->lib(), &_external->db(), name, derivationPath, words,
                                                       std::move(created));
}

void Wallet::queryWalletAddress(const Callback<QString> &done) {
  Expects(_originalKeyCreator != nullptr);
  Expects(_configInfo.has_value());

  _originalKeyCreator->queryWalletAddress(_configInfo->restrictedInitPublicKey, done);
}

void Wallet::saveOriginalKey(const QByteArray &password, const QString &address, const Callback<QByteArray> &done) {
  Expects(_originalKeyCreator != nullptr);

  auto saved = [=](Result<WalletList::Entry> result) {
    if (!result) {
      return InvokeCallback(done, result.error());
    }
    const auto destroyed = base::take(_originalKeyCreator);
    _list->entries.push_back(*result);
    InvokeCallback(done, result->publicKey);
  };
  _originalKeyCreator->save(
      password, *_list,
      (address.isEmpty() ? getDefaultAddress(_originalKeyCreator->key(), kDefaultWorkchainId) : address),
      settings().useTestNetwork, std::move(saved));
}

void Wallet::saveFtabiKey(const QByteArray &password, const Callback<QByteArray> &done) {
  Expects(_ftabiKeyCreator != nullptr);

  auto saved = [=](Result<WalletList::FtabiEntry> result) {
    if (!result) {
      return InvokeCallback(done, result.error());
    }
    const auto destroyed = base::take(_ftabiKeyCreator);
    _list->ftabiEntries.push_back(*result);
    InvokeCallback(done, result->publicKey);
  };
  _ftabiKeyCreator->save(password, *_list, settings().useTestNetwork, std::move(saved));
}

void Wallet::exportKey(const QByteArray &publicKey, const QByteArray &password,
                       const Callback<std::vector<QString>> &done) {
  _external->lib()
      .request(TLExportKey(prepareInputKey(publicKey, password)))
      .done([=](const TLExportedKey &result) { InvokeCallback(done, Parse(result)); })
      .fail([=](const TLError &error) { InvokeCallback(done, ErrorFromLib(error)); })
      .send();
}

void Wallet::exportFtabiKey(const QByteArray &publicKey, const QByteArray &password,
                            const Callback<std::pair<QString, std::vector<QString>>> &done) {
  _external->lib()
      .request(TLExportKey(prepareInputKey(publicKey, password)))
      .done([=](const TLExportedKey &result) {
        result.match(
            [&](const TLDftabi_exportedKey &result) {
              std::vector<QString> wordsList;
              wordsList.reserve(result.vword_list().v.size());
              for (const auto &word : result.vword_list().v) {
                wordsList.emplace_back(word.v);
              }
              InvokeCallback(done, std::make_pair(result.vderivation_path().v, std::move(wordsList)));
            },
            [&](auto &&) {
              InvokeCallback(done, Error{Error::Type::TonLib, "Failed to export ftabi key"});
            });
      })
      .fail([=](const TLError &error) { InvokeCallback(done, ErrorFromLib(error)); })
      .send();
}

TLinputKey Wallet::prepareInputKey(const QByteArray &publicKey, const QByteArray &password) const {
  const auto find =
      [&](const auto &entries, const auto &fieldSelector,
          const Fn<TLinputKey(const TLkey &, const TLsecureString &)> &wrapper) -> std::optional<TLinputKey> {
    const auto i = ranges::find(entries, publicKey, fieldSelector);
    if (i == end(entries)) {
      return std::nullopt;
    }
    return wrapper(tl_key(tl_string(publicKey), TLsecureBytes{i->secret}), TLsecureBytes{password});
  };

  if (auto entry = find(_list->entries, SelectConstField(&WalletList::Entry::publicKey), tl_inputKeyRegular)) {
    return entry.value();
  } else if (auto ftabiEntry =
                 find(_list->ftabiEntries, SelectConstField(&WalletList::FtabiEntry::publicKey), tl_inputKeyFtabi)) {
    return ftabiEntry.value();
  } else {
    Unexpected("Key not found");
  }
}

void Wallet::setWalletList(const WalletList &list) {
  Expects(_list->entries.empty());

  *_list = list;
}

void Wallet::deleteKey(const QByteArray &publicKey, const Callback<> &done) {
  Expects(_originalKeyCreator == nullptr);
  Expects(_keyDestroyer == nullptr);
  Expects(_passwordChanger == nullptr);
  Expects(ranges::contains(_list->entries, publicKey, &WalletList::Entry::publicKey));

  auto list = *_list;
  const auto index = ranges::find(list.entries, publicKey, &WalletList::Entry::publicKey) - begin(list.entries);

  auto removed = [=](Result<> result) {
    const auto destroyed = base::take(_keyDestroyer);
    if (!result) {
      return InvokeCallback(done, result);
    }
    _list->entries.erase(begin(_list->entries) + index);
    _viewersPasswords.erase(publicKey);
    _viewersPasswordsWaiters.erase(publicKey);
    InvokeCallback(done, result);
  };
  _keyDestroyer =
      std::make_unique<KeyDestroyer>(&_external->lib(), &_external->db(), std::move(list), KeyType::Original, index,
                                     settings().useTestNetwork, std::move(removed));
}

void Wallet::deleteFtabiKey(const QByteArray &publicKey, const Callback<> &done) {
  Expects(_keyDestroyer == nullptr);
  Expects(ranges::contains(_list->ftabiEntries, publicKey, &WalletList::FtabiEntry::publicKey));

  auto list = *_list;
  const auto index =
      ranges::find(list.ftabiEntries, publicKey, &WalletList::FtabiEntry::publicKey) - begin(list.ftabiEntries);

  auto removed = [=](Result<> result) {
    const auto destroyed = base::take(_keyDestroyer);
    if (!result) {
      return InvokeCallback(done, result);
    }
    _list->ftabiEntries.erase(begin(_list->ftabiEntries) + index);
    InvokeCallback(done, result);
  };
  _keyDestroyer = std::make_unique<KeyDestroyer>(&_external->lib(), &_external->db(), std::move(list), KeyType::Ftabi,
                                                 index, settings().useTestNetwork, std::move(removed));
}

void Wallet::deleteAllKeys(const Callback<> &done) {
  Expects(_originalKeyCreator == nullptr);
  Expects(_keyDestroyer == nullptr);
  Expects(_passwordChanger == nullptr);

  auto removed = [=](Result<> result) {
    const auto destroyed = base::take(_keyDestroyer);
    if (!result) {
      return InvokeCallback(done, result);
    }
    _list->entries.clear();
    _viewersPasswords.clear();
    _viewersPasswordsWaiters.clear();
    InvokeCallback(done, result);
  };
  _keyDestroyer = std::make_unique<KeyDestroyer>(&_external->lib(), &_external->db(), settings().useTestNetwork,
                                                 std::move(removed));
}

void Wallet::changePassword(const QByteArray &oldPassword, const QByteArray &newPassword, const Callback<> &done) {
  Expects(_originalKeyCreator == nullptr);
  Expects(_keyDestroyer == nullptr);
  Expects(_passwordChanger == nullptr);
  Expects(!_list->entries.empty());

  auto changed = [=](Result<std::vector<QByteArray>> result) {
    const auto destroyed = base::take(_passwordChanger);
    if (!result) {
      return InvokeCallback(done, result.error());
    }
    Assert(result->size() == _list->entries.size());
    for (auto i = 0, count = int(result->size()); i != count; ++i) {
      _list->entries[i].secret = (*result)[i];
    }
    for (auto &[publicKey, password] : _viewersPasswords) {
      updateViewersPassword(publicKey, newPassword);
    }
    InvokeCallback(done);
  };
  _passwordChanger = std::make_unique<PasswordChanger>(&_external->lib(), &_external->db(), oldPassword, newPassword,
                                                       *_list, settings().useTestNetwork, std::move(changed));
}

void Wallet::changeFtabiPassword(const QByteArray &publicKey, const QByteArray &oldPassword,
                                 const QByteArray &newPassword, const Callback<> &done) {
  auto changed = [=](const Result<QByteArray> &result) {
    const auto destroyed = base::take(_ftabiPasswordChanger);
    if (!result) {
      return InvokeCallback(done, result.error());
    }
    auto it = std::find_if(_list->ftabiEntries.begin(), _list->ftabiEntries.end(),
                           [&](const auto &entry) { return entry.publicKey == publicKey; });
    Assert(it != _list->ftabiEntries.end());
    it->secret = result.value();
    InvokeCallback(done);
  };
  _ftabiPasswordChanger = std::make_unique<FtabiPasswordChanger>(  //
      &_external->lib(), &_external->db(), oldPassword, newPassword, *_list, publicKey, settings().useTestNetwork,
      std::move(changed));
}

void Wallet::checkSendGrams(const QByteArray &publicKey, const TransactionToSend &transaction,
                            const Callback<TransactionCheckResult> &done) {
  Expects(transaction.amount >= 0);

  const auto sender = getUsedAddress(publicKey);
  Assert(!sender.isEmpty());

  checkTransactionFees(sender, transaction.recipient, tl_msg_dataText(tl_string(transaction.comment)),
                       transaction.amount, transaction.timeout, transaction.allowSendToUninited, done);
}

void Wallet::checkSendTokens(const QByteArray &publicKey, const TokenTransactionToSend &transaction,
                             const Callback<std::pair<TransactionCheckResult, TokenTransferCheckResult>> &done) {
  Expects(transaction.amount >= 0);

  const auto sender = getUsedAddress(publicKey);
  Assert(!sender.isEmpty());

  if (transaction.tokenTransferType == TokenTransferType::SwapBack) {
    const auto ethereumAddress = ParseEthereumAddress(transaction.recipient);
    if (!ethereumAddress.has_value()) {
      return InvokeCallback(done, std::make_pair(TransactionCheckResult{}, InvalidEthAddress{}));
    }

    return CreateSwapBackMessage(
        _external->lib(), *ethereumAddress, transaction.callbackAddress, transaction.amount,
        [=](Result<QByteArray> &&body) {
          if (!body.has_value()) {
            return InvokeCallback(done, body.error());
          }
          return checkTransactionFees(  //
              sender, transaction.walletContractAddress, tl_msg_dataRaw(tl_bytes(body.value()), tl_bytes()),
              TokenTransactionToSend::realAmount, transaction.timeout, false,
              [=](Result<TransactionCheckResult> &&result) {
                if (result.has_value()) {
                  InvokeCallback(done, std::make_pair(std::move(result.value()), TokenTransferUnchanged{}));
                } else {
                  InvokeCallback(done, result.error());
                }
              });
        });
  }

  const auto checkWalletAddress = [=](const QString &recipientTokenWallet) {
    _external->lib()
        .request(TLGetAccountState(tl_accountAddress(tl_string(recipientTokenWallet))))
        .done([=](const TLFullAccountState &result) {
          const auto isUninit = result.c_fullAccountState().vaccount_state().type() == id_uninited_accountState;

          if (isUninit && transaction.tokenTransferType == TokenTransferType::Direct) {
            InvokeCallback(done, std::make_pair(TransactionCheckResult{}, DirectAccountNotFound{}));
          } else if (isUninit) {
            CreateTokenTransferToOwnerMessage(
                _external->lib(), transaction.recipient, transaction.amount, TokenTransactionToSend::initialBalance,
                [=](const Result<QByteArray> &body) {
                  if (!body.has_value()) {
                    return InvokeCallback(done, body.error());
                  }
                  checkTransactionFees(  //
                      sender, transaction.walletContractAddress, tl_msg_dataRaw(tl_bytes(body.value()), tl_bytes()),
                      TokenTransactionToSend::realAmount, transaction.timeout, false,
                      [=](Result<TransactionCheckResult> result) {
                        if (result.has_value()) {
                          InvokeCallback(done, std::make_pair(std::move(result.value()), TokenTransferUnchanged{}));
                        } else {
                          InvokeCallback(done, result.error());
                        }
                      });
                });
          } else {
            CreateTokenMessage(
                _external->lib(), recipientTokenWallet, transaction.amount, [=](Result<QByteArray> &&body) {
                  if (!body.has_value()) {
                    return InvokeCallback(done, body.error());
                  }
                  auto transferCheckResult = transaction.tokenTransferType == TokenTransferType::ToOwner
                                                 ? TokenTransferCheckResult{DirectRecipient{recipientTokenWallet}}
                                                 : TokenTransferCheckResult{TokenTransferUnchanged{}};
                  checkTransactionFees(  //
                      sender, transaction.walletContractAddress, tl_msg_dataRaw(tl_bytes(body.value()), tl_bytes()),
                      TokenTransactionToSend::realAmount, transaction.timeout, false,
                      [=](Result<TransactionCheckResult> result) {
                        if (result.has_value()) {
                          InvokeCallback(done, std::make_pair(std::move(result.value()), transferCheckResult));
                        } else {
                          InvokeCallback(done, result.error());
                        }
                      });
                });
          }
        })
        .fail([=](const TLError &error) { InvokeCallback(done, ErrorFromLib(error)); })
        .send();
  };

  if (transaction.tokenTransferType == Ton::TokenTransferType::ToOwner) {
    _external->lib()
        .request(TLftabi_RunLocal(                                          //
            tl_accountAddress(tl_string(transaction.rootContractAddress)),  //
            RootTokenGetWalletAddressFunction(),                            //
            tl_ftabi_functionCallExternal({}, tl_vector(QVector<TLftabi_Value>{
                                                  PackPubKey(),                        //
                                                  PackAddress(transaction.recipient),  //
                                              }))))
        .done([=, rootContractAddress = transaction.rootContractAddress,
               ownerAddress = transaction.recipient](const TLftabi_tvmOutput &result) {
          const auto &output = result.c_ftabi_tvmOutput();
          if (output.vsuccess().type() != id_boolTrue) {
            return InvokeCallback(done, ErrorFromLib(GenerateVmError(output.vexit_code())));
          }

          const auto &tokens = output.vvalues().v;
          const auto walletAddress = UnpackAddress(tokens[0]);

          _external->updateTokenOwnersCache(rootContractAddress, walletAddress, ownerAddress,
                                            [=](const Result<> &) { checkWalletAddress(walletAddress); });
        })
        .fail([=](const TLError &error) { InvokeCallback(done, ErrorFromLib(error)); })
        .send();
  } else if (transaction.tokenTransferType == Ton::TokenTransferType::Direct) {
    checkWalletAddress(transaction.recipient);
  } else {
    Unexpected("Unreachable");
  }
}

void Wallet::checkSendStake(const QByteArray &publicKey, const StakeTransactionToSend &transaction,
                            const Callback<TransactionCheckResult> &done) {
  Expects(transaction.stake >= 0);

  const auto sender = getUsedAddress(publicKey);
  Assert(!sender.isEmpty());

  CreateStakeMessage(_external->lib(), transaction.stake, [=](Result<QByteArray> &&body) {
    if (!body.has_value()) {
      return InvokeCallback(done, body.error());
    }

    const auto realAmount = StakeTransactionToSend::depoolFee + transaction.stake;
    checkTransactionFees(sender, transaction.depoolAddress, tl_msg_dataRaw(tl_bytes(body.value()), tl_bytes()),
                         realAmount, transaction.timeout, false, done);
  });
}

void Wallet::checkWithdraw(const QByteArray &publicKey, const WithdrawalTransactionToSend &transaction,
                           const Callback<TransactionCheckResult> &done) {
  Expects(transaction.all || transaction.amount >= 0);

  const auto sender = getUsedAddress(publicKey);
  Assert(!sender.isEmpty());

  CreateWithdrawalMessage(_external->lib(), transaction.amount, transaction.all, [=](Result<QByteArray> &&body) {
    if (!body.has_value()) {
      return InvokeCallback(done, body.error());
    }

    checkTransactionFees(sender, transaction.depoolAddress, tl_msg_dataRaw(tl_bytes(body.value()), tl_bytes()),
                         WithdrawalTransactionToSend::depoolFee, transaction.timeout, false, done);
  });
}

void Wallet::checkCancelWithdraw(const QByteArray &publicKey, const CancelWithdrawalTransactionToSend &transaction,
                                 const Callback<TransactionCheckResult> &done) {
  const auto sender = getUsedAddress(publicKey);
  Assert(!sender.isEmpty());

  CreateCancelWithdrawalMessage(_external->lib(), [=](Result<QByteArray> &&body) {
    if (!body.has_value()) {
      return InvokeCallback(done, body.error());
    }

    checkTransactionFees(sender, transaction.depoolAddress, tl_msg_dataRaw(tl_bytes(body.value()), tl_bytes()),
                         CancelWithdrawalTransactionToSend::depoolFee, transaction.timeout, false, done);
  });
}

void Wallet::checkDeployTokenWallet(const QByteArray &publicKey, const DeployTokenWalletTransactionToSend &transaction,
                                    const Callback<TransactionCheckResult> &done) {
  const auto sender = getUsedAddress(publicKey);
  Assert(!sender.isEmpty());

  CreateTokenWalletDeployMessage(
      _external->lib(), DeployTokenWalletTransactionToSend::initialBalance, sender, [=](Result<QByteArray> &&body) {
        if (!body.has_value()) {
          return InvokeCallback(done, body.error());
        }

        checkTransactionFees(sender, transaction.rootContractAddress,
                             tl_msg_dataRaw(tl_bytes(body.value()), tl_bytes()),
                             DeployTokenWalletTransactionToSend::realAmount, transaction.timeout, false, done);
      });
}

void Wallet::checkCollectTokens(const QByteArray &publicKey, const CollectTokensTransactionToSend &transaction,
                                const Callback<TransactionCheckResult> &done) {
  const auto sender = getUsedAddress(publicKey);
  Assert(!sender.isEmpty());

  CreateExecuteProxyCallbackMessage(_external->lib(), [=](Result<QByteArray> &&body) {
    if (!body.has_value()) {
      return InvokeCallback(done, body.error());
    }

    checkTransactionFees(sender, transaction.eventContractAddress, tl_msg_dataRaw(tl_bytes(body.value()), tl_bytes()),
                         CollectTokensTransactionToSend::realAmount, transaction.timeout, true, done);
  });
}

void Wallet::checkDeployMultisig(const DeployMultisigTransactionToSend &transaction,
                                 const Callback<TransactionCheckResult> &done) {
  const auto check = makeEstimateFeesCallback(done);

  CreateMultisigConstructorMessage(  //
      _external->lib(), tl_inputKeyFake(), transaction.requiredConfirmations, transaction.owners,
      [=](Result<QByteArray> &&body) {
        if (!body.has_value()) {
          return InvokeCallback(done, body.error());
        }

        std::cout << "Created message" << std::endl;

        _external->lib()
            .request(TLraw_CreateQueryTvc(tl_accountAddress(tl_string(transaction.initialInfo.address)),
                                          tl_int32(transaction.timeout), tl_bytes(transaction.initialInfo.initState),
                                          tl_bytes(body.value())))
            .done([=](const TLquery_Info &result) {
              std::cout << "Created query" << std::endl;
              result.match([&](const TLDquery_info &data) { check(data.vid().v); });
            })
            .fail([=](const TLError &error) {
              std::cout << "Failed query" << std::endl;
              InvokeCallback(done, ErrorFromLib(error));
            })
            .send();
      });
}

void Wallet::checkSubmitTransaction(const SubmitTransactionToSend &transaction,
                                    const Callback<TransactionCheckResult> &done) {
  const auto check = makeEstimateFeesCallback(done);

  CreateMultisigSubmitTransactionMessage(  //
      _external->lib(), tl_inputKeyFake(), transaction.dest, transaction.value, transaction.bounce, transaction.payload,
      [=](Result<QByteArray> &&body) {
        if (!body.has_value()) {
          return InvokeCallback(done, body.error());
        }
        _external->lib()
            .request(TLraw_CreateQueryTvc(tl_accountAddress(tl_string(transaction.multisigAddress)),
                                          tl_int32(transaction.timeout), {}, tl_bytes(body.value())))
            .done([=](const TLquery_Info &result) {
              result.match([&](const TLDquery_info &data) { check(data.vid().v); });
            })
            .fail([=](const TLError &error) { InvokeCallback(done, ErrorFromLib(error)); })
            .send();
      });
}

void Wallet::checkConfirmTransaction(const ConfirmTransactionToSend &transaction,
                                     const Callback<TransactionCheckResult> &done) {
  const auto check = makeEstimateFeesCallback(done);

  CreateMultisigConfirmTransactionMessage(  //
      _external->lib(), tl_inputKeyFake(), transaction.transactionId, [=](Result<QByteArray> &&body) {
        if (!body.has_value()) {
          return InvokeCallback(done, body.error());
        }
        _external->lib()
            .request(TLraw_CreateQueryTvc(tl_accountAddress(tl_string(transaction.multisigAddress)),
                                          tl_int32(transaction.timeout), {}, tl_bytes(body.value())))
            .done([=](const TLquery_Info &result) {
              result.match([&](const TLDquery_info &data) { check(data.vid().v); });
            })
            .fail([=](const TLError &error) { InvokeCallback(done, ErrorFromLib(error)); })
            .send();
      });
}

void Wallet::sendGrams(const QByteArray &publicKey, const QByteArray &password, const TransactionToSend &transaction,
                       const Callback<PendingTransaction> &ready, const Callback<> &done) {
  Expects(transaction.amount >= 0);

  const auto sender = getUsedAddress(publicKey);
  Assert(!sender.isEmpty());

  sendMessage(publicKey, password, sender, transaction.recipient, tl_msg_dataText(tl_string(transaction.comment)),
              transaction.amount, transaction.timeout, transaction.allowSendToUninited, transaction.comment, ready,
              done);
}

void Wallet::sendTokens(const QByteArray &publicKey, const QByteArray &password,
                        const TokenTransactionToSend &transaction, const Callback<PendingTransaction> &ready,
                        const Callback<> &done) {
  Expects(transaction.amount >= 0);

  const auto sender = getUsedAddress(publicKey);
  Assert(!sender.isEmpty());

  const auto bodyCreated = [=](Result<QByteArray> &&body) {
    if (!body.has_value()) {
      return InvokeCallback(ready, body.error());
    }

    const auto realAmount = TokenTransactionToSend::realAmount;

    sendMessage(publicKey, password, sender, transaction.walletContractAddress,
                tl_msg_dataRaw(tl_bytes(body.value()), tl_bytes()), realAmount, transaction.timeout, false, ready,
                done);
  };

  switch (transaction.tokenTransferType) {
    case TokenTransferType::Direct:
      return CreateTokenMessage(_external->lib(), transaction.recipient, transaction.amount, bodyCreated);
    case TokenTransferType::ToOwner:
      return CreateTokenTransferToOwnerMessage(_external->lib(), transaction.recipient, transaction.amount,
                                               TokenTransactionToSend::initialBalance, bodyCreated);
    case TokenTransferType::SwapBack: {
      const auto ethereumAddress = ParseEthereumAddress(transaction.recipient);
      if (!ethereumAddress.has_value()) {
        return InvokeCallback(ready, Error{Error::Type::Web, "Invalid ethereum address"});
      }
      return CreateSwapBackMessage(_external->lib(), *ethereumAddress, transaction.callbackAddress, transaction.amount,
                                   bodyCreated);
    }
    default:
      Unexpected("Token transfer type");
  }
}

void Wallet::sendStake(const QByteArray &publicKey, const QByteArray &password,
                       const StakeTransactionToSend &transaction, const Callback<PendingTransaction> &ready,
                       const Callback<> &done) {
  Expects(transaction.stake >= 0);

  const auto sender = getUsedAddress(publicKey);
  Assert(!sender.isEmpty());

  CreateStakeMessage(_external->lib(), transaction.stake, [=](Result<QByteArray> &&body) {
    if (!body.has_value()) {
      return InvokeCallback(ready, body.error());
    }

    const auto realAmount = StakeTransactionToSend::depoolFee + transaction.stake;

    sendMessage(publicKey, password, sender, transaction.depoolAddress,
                tl_msg_dataRaw(tl_bytes(body.value()), tl_bytes()), realAmount, transaction.timeout, false, ready,
                done);
  });
}

void Wallet::withdraw(const QByteArray &publicKey, const QByteArray &password,
                      const WithdrawalTransactionToSend &transaction, const Callback<PendingTransaction> &ready,
                      const Callback<> &done) {
  Expects(transaction.all || transaction.amount >= 0);

  const auto sender = getUsedAddress(publicKey);
  Assert(!sender.isEmpty());

  CreateWithdrawalMessage(_external->lib(), transaction.amount, transaction.all, [=](Result<QByteArray> &&body) {
    if (!body.has_value()) {
      return InvokeCallback(ready, body.error());
    }

    const auto realAmount = WithdrawalTransactionToSend::depoolFee;

    sendMessage(publicKey, password, sender, transaction.depoolAddress,
                tl_msg_dataRaw(tl_bytes(body.value()), tl_bytes()), realAmount, transaction.timeout, false, ready,
                done);
  });
}

void Wallet::cancelWithdrawal(const QByteArray &publicKey, const QByteArray &password,
                              const CancelWithdrawalTransactionToSend &transaction,
                              const Callback<PendingTransaction> &ready, const Callback<> &done) {
  const auto sender = getUsedAddress(publicKey);
  Assert(!sender.isEmpty());

  CreateCancelWithdrawalMessage(_external->lib(), [=](Result<QByteArray> &&body) {
    if (!body.has_value()) {
      return InvokeCallback(ready, body.error());
    }

    const auto realAmount = CancelWithdrawalTransactionToSend::depoolFee;

    sendMessage(publicKey, password, sender, transaction.depoolAddress,
                tl_msg_dataRaw(tl_bytes(body.value()), tl_bytes()), realAmount, transaction.timeout, false, ready,
                done);
  });
}

void Wallet::deployTokenWallet(const QByteArray &publicKey, const QByteArray &password,
                               const DeployTokenWalletTransactionToSend &transaction,
                               const Callback<PendingTransaction> &ready, const Callback<> &done) {
  const auto sender = getUsedAddress(publicKey);
  Assert(!sender.isEmpty());

  CreateTokenWalletDeployMessage(  //
      _external->lib(), DeployTokenWalletTransactionToSend::initialBalance, sender, [=](Result<QByteArray> &&body) {
        if (!body.has_value()) {
          return InvokeCallback(ready, body.error());
        }

        const auto realAmount = DeployTokenWalletTransactionToSend::realAmount;

        sendMessage(publicKey, password, sender, transaction.rootContractAddress,
                    tl_msg_dataRaw(tl_bytes(body.value()), tl_bytes()), realAmount, transaction.timeout, false, ready,
                    done);
      });
}

void Wallet::collectTokens(const QByteArray &publicKey, const QByteArray &password,
                           const CollectTokensTransactionToSend &transaction, const Callback<PendingTransaction> &ready,
                           const Callback<> &done) {
  const auto sender = getUsedAddress(publicKey);
  Assert(!sender.isEmpty());

  CreateExecuteProxyCallbackMessage(_external->lib(), [=](Result<QByteArray> &&body) {
    if (!body.has_value()) {
      return InvokeCallback(ready, body.error());
    }

    const auto realAmount = CollectTokensTransactionToSend::realAmount;

    sendMessage(publicKey, password, sender, transaction.eventContractAddress,
                tl_msg_dataRaw(tl_bytes(body.value()), tl_bytes()), realAmount, transaction.timeout, true, ready, done);
  });
}

void Wallet::deployMultisig(const QByteArray &publicKey, const QByteArray &password,
                            const DeployMultisigTransactionToSend &transaction,
                            const Callback<PendingTransaction> &ready, const Callback<> &done) {
  const auto sender = getUsedAddress(publicKey);
  Assert(!sender.isEmpty());

  CreateMultisigConstructorMessage(  //
      _external->lib(), prepareInputKey(transaction.initialInfo.publicKey, password), transaction.requiredConfirmations,
      transaction.owners, [=](Result<QByteArray> &&body) {
        if (!body.has_value()) {
          return InvokeCallback(ready, body.error());
        }
        sendExternalMessage(sender, transaction.initialInfo.address, transaction.timeout,
                            transaction.initialInfo.initState, body.value(), ready, done);
      });
}

void Wallet::submitTransaction(const QByteArray &publicKey, const QByteArray &password,
                               const SubmitTransactionToSend &transaction, const Callback<PendingTransaction> &ready,
                               const Callback<> &done) {
  const auto sender = getUsedAddress(publicKey);
  Assert(!sender.isEmpty());

  CreateMultisigSubmitTransactionMessage(  //
      _external->lib(), prepareInputKey(transaction.publicKey, password), transaction.dest, transaction.value,
      transaction.bounce, transaction.payload, [=](Result<QByteArray> &&body) {
        if (!body.has_value()) {
          return InvokeCallback(ready, body.error());
        }
        sendExternalMessage(sender, transaction.multisigAddress, transaction.timeout, {}, body.value(), ready, done);
      });
}

void Wallet::confirmTransaction(const QByteArray &publicKey, const QByteArray &password,
                                const ConfirmTransactionToSend &transaction, const Callback<PendingTransaction> &ready,
                                const Callback<> &done) {
  const auto sender = getUsedAddress(publicKey);
  Assert(!sender.isEmpty());

  CreateMultisigConfirmTransactionMessage(  //
      _external->lib(), prepareInputKey(transaction.publicKey, password), transaction.transactionId,
      [=](Result<QByteArray> &&body) {
        if (!body.has_value()) {
          return InvokeCallback(ready, body.error());
        }
        sendExternalMessage(sender, transaction.multisigAddress, transaction.timeout, {}, body.value(), ready, done);
      });
}

void Wallet::openGate(const QString &rawAddress, const std::optional<Symbol> &token) {
  auto url = QUrl(_gateUrl);
  auto params = "TONAddress=" + rawAddress;

  // TODO:

  if (token.has_value()) {
    params += "&ethereumTokenAddress=";
  }

  url.setQuery(params);
  QDesktopServices::openUrl(url);
}

void Wallet::openGateExecuteSwapBack(const QString &eventAddress) {
  auto url = QUrl(_gateUrl).resolved(QUrl{"ton-to-eth"});
  url.setQuery(QString{"event=%1"}.arg(ConvertIntoRaw(eventAddress)));
  QDesktopServices::openUrl(url);
}

void Wallet::addDePool(const QByteArray &publicKey, const QString &dePoolAddress, const Callback<> &done) {
  const auto account = getUsedAddress(publicKey);
  const auto packedDePoolAddress = ConvertIntoPacked(dePoolAddress);

  _external->lib()
      .request(TLGetAccountState(tl_accountAddress(tl_string(packedDePoolAddress))))
      .done([this, done, account, packedDePoolAddress](const TLFullAccountState &result) {
        const auto &codeHash = result.c_fullAccountState().vcode_hash().v;
        const auto dePoolVersion = GuessDePoolVersion(codeHash);

        if (result.c_fullAccountState().vaccount_state().type() != id_raw_accountState || !dePoolVersion.has_value()) {
          return InvokeCallback(done, Error{Error::Type::TonLib, "Requested account is not a DePool"});
        }

        const auto &info = result.c_fullAccountState();
        const auto &accountState = result.c_fullAccountState().vaccount_state().c_raw_accountState();

        _external->lib()
            .request(TLftabi_RunLocalCachedSplit(                              //
                tl_accountAddress(tl_string(packedDePoolAddress)),             //
                info.vlast_transaction_id().c_internal_transactionId().vlt(),  //
                tl_int32(static_cast<int32>(info.vsync_utime().v)),            //
                info.vbalance(),                                               //
                accountState.vdata(),                                          //
                accountState.vcode(),                                          //
                DePoolParticipantInfoFunction(*dePoolVersion),                 //
                tl_ftabi_functionCallExternal(                                 //
                    {},                                                        // header values
                    tl_vector(QVector<TLftabi_Value>{
                        PackAddress(account),  // account
                    }))))
            .done([=](const TLftabi_tvmOutput &result) {
              auto state = ParseDePoolParticipantState(*dePoolVersion, result);
              if (state.has_value()) {
                _accountViewers->addDePool(account, packedDePoolAddress, std::move(*state));
                InvokeCallback(done);
              } else {
                InvokeCallback(done, Error{Error::Type::TonLib, "Invalid DePool ABI"});
              }
            })
            .fail([=](const TLError &error) {
              _accountViewers->addDePool(account, packedDePoolAddress,
                                         DePoolParticipantState{.version = *dePoolVersion});
              InvokeCallback(done);
            })
            .send();
      })
      .fail([=](const TLError &error) { InvokeCallback(done, ErrorFromLib(error)); })
      .send();
}

void Wallet::removeDePool(const QByteArray &publicKey, const QString &dePoolAddress) {
  _accountViewers->removeDePool(getUsedAddress(publicKey), dePoolAddress);
}

void Wallet::addToken(const QByteArray &publicKey, const QString &rootContractAddress, const Callback<> &done) {
  const auto account = getUsedAddress(publicKey);
  const auto packedRootContractAddress = ConvertIntoPacked(rootContractAddress);

  const auto getWalletAddress = [this, done, account, packedRootContractAddress](
                                    TLFullAccountState &&result, const RootTokenContractDetails &details) {
    const auto &info = result.c_fullAccountState();
    const auto &accountState = result.c_fullAccountState().vaccount_state().c_raw_accountState();

    _external->lib()
        .request(TLftabi_RunLocalCachedSplit(                              //
            tl_accountAddress(tl_string(packedRootContractAddress)),       //
            info.vlast_transaction_id().c_internal_transactionId().vlt(),  //
            tl_int32(static_cast<int32>(info.vsync_utime().v)),            //
            info.vbalance(),                                               //
            accountState.vdata(),                                          //
            accountState.vcode(),                                          //
            RootTokenGetWalletAddressFunction(),                           //
            tl_ftabi_functionCallExternal({}, tl_vector(QVector<TLftabi_Value>{
                                                  PackPubKey(),          //
                                                  PackAddress(account),  //
                                              }))))
        .done([=](const TLftabi_tvmOutput &result) {
          const auto &output = result.c_ftabi_tvmOutput();
          if (output.vsuccess().type() != id_boolTrue) {
            return InvokeCallback(done, ErrorFromLib(GenerateVmError(output.vexit_code())));
          }

          const auto &tokens = output.vvalues().v;
          const auto walletAddress = UnpackAddress(tokens[0]);

          auto getBalance = [=](TokenState tokenState) mutable {
            _external->lib()
                .request(TLftabi_RunLocal(                        //
                    tl_accountAddress(tl_string(walletAddress)),  //
                    TokenGetBalanceFunction(),                    //
                    tl_ftabi_functionCallExternal({}, {})))
                .done([=](const TLftabi_tvmOutput &tvmResult) mutable {
                  const auto &output = tvmResult.c_ftabi_tvmOutput();
                  if (output.vsuccess().type() != id_boolTrue) {
                    std::cout << "failed to get balance: " << output.vexit_code().v << std::endl;
                    return InvokeCallback(done, ErrorFromLib(GenerateVmError(output.vexit_code())));
                  }

                  const auto &results = output.vvalues().v;
                  if (results.empty() || !IsBigInt(results[0])) {
                    std::cout << "failed to parse results: " << results.size() << std::endl;
                    return InvokeCallback(done, Error{Error::Type::TonLib, "failed to parse results"});
                  }

                  tokenState.balance = UnpackUint128(results[0]);
                  _accountViewers->addToken(account, std::move(tokenState));
                  InvokeCallback(done);
                })
                .fail([=](const TLError &error) mutable {
                  _accountViewers->addToken(account, std::move(tokenState));
                  InvokeCallback(done);
                })
                .send();
          };

          getBalance(TokenState{.token = Symbol::tip3(details.symbol, details.decimals, packedRootContractAddress),
                                .walletContractAddress = walletAddress,
                                .rootOwnerAddress = details.ownerAddress,
                                .balance = 0});
        })
        .fail([=](const TLError &error) {
          std::cout << "error in RootTokenContract.getWalletAddress: " << error.c_error().vmessage().v.toStdString()
                    << std::endl;
          InvokeCallback(done, ErrorFromLib(error));
        })
        .send();
  };

  _external->lib()
      .request(TLGetAccountState(tl_accountAddress(tl_string(packedRootContractAddress))))
      .done([this, done, account, packedRootContractAddress, getWalletAddress](TLFullAccountState &&result) {
        if (result.c_fullAccountState().vaccount_state().type() != id_raw_accountState) {
          return InvokeCallback(done, Error{Error::Type::TonLib, "Requested account is not a root token contract"});
        }

        const auto &info = result.c_fullAccountState();
        const auto &accountState = result.c_fullAccountState().vaccount_state().c_raw_accountState();

        _external->lib()
            .request(TLftabi_RunLocalCachedSplit(                                               //
                tl_accountAddress(tl_string(packedRootContractAddress)),                        //
                tl_int64(info.vlast_transaction_id().c_internal_transactionId().vlt().v + 10),  //
                tl_int32(static_cast<int32>(info.vsync_utime().v)),                             //
                info.vbalance(),                                                                //
                accountState.vdata(),                                                           //
                accountState.vcode(),                                                           //
                RootTokenGetDetailsFunction(),                                                  //
                tl_ftabi_functionCallExternal({}, {})))
            .done([=, result = std::forward<TLFullAccountState>(result)](const TLftabi_tvmOutput &tvmResult) mutable {
              const auto &output = tvmResult.c_ftabi_tvmOutput();
              if (output.vsuccess().type() != id_boolTrue) {
                return InvokeCallback(done, ErrorFromLib(GenerateVmError(output.vexit_code())));
              }

              auto details = ParseRootTokenContractDetails(output.vvalues());
              if (details.has_value()) {
                getWalletAddress(std::move(result), *details);
              } else {
                InvokeCallback(done, Error{Error::Type::TonLib, "Invalid RootTokenContract.getDetails ABI"});
              }
            })
            .fail([=](const TLError &error) {
              std::cout << "error in RootTokenContract.getDetails: " << error.c_error().vmessage().v.toStdString()
                        << std::endl;
              InvokeCallback(done, Error{Error::Type::TonLib, "Failed to get root token contract details"});
            })
            .send();
      })
      .fail([=](const TLError &error) { InvokeCallback(done, ErrorFromLib(error)); })
      .send();
}

void Wallet::removeToken(const QByteArray &publicKey, const Symbol &token) {
  _accountViewers->removeToken(getUsedAddress(publicKey), token);
}

void Wallet::addMultisig(const QByteArray &publicKey, const MultisigInfo &info, const QByteArray &custodianPublicKey,
                         const Callback<> &done) {
  const auto account = getUsedAddress(publicKey);

  requestState(info.address, [=](Result<AccountState> result) mutable {
    if (!result.has_value()) {
      return InvokeCallback(done, result.error());
    }
    auto accountState = std::move(result.value());

    const auto lastTransactionId = accountState.lastTransactionId;

    requestTransactions(    //
        info.address,       //
        lastTransactionId,  //
        [=, accountState = std::move(accountState)](Result<TransactionsSlice> lastTransactions) mutable {
          if (!lastTransactions.has_value()) {
            return InvokeCallback(done, lastTransactions.error());
          }

          _accountViewers->addMultisig(  //
              account, info.address,
              MultisigState{
                  .version = info.version,
                  .publicKey = custodianPublicKey,
                  .accountState = std::move(accountState),
                  .lastTransactions = std::move(*lastTransactions),
                  .custodians = std::move(info.custodians),
                  .expirationTime = info.expirationTime,
              });
          InvokeCallback(done);
        });
  });
}

void Wallet::removeMultisig(const QByteArray &publicKey, const QString &multisigAddress) {
  _accountViewers->removeMultisig(getUsedAddress(publicKey), multisigAddress);
}

void Wallet::reorderAssets(const QByteArray &publicKey, int oldPosition, int newPosition) {
  _accountViewers->reorderAssets(getUsedAddress(publicKey), oldPosition, newPosition);
}

void Wallet::requestState(const QString &address, const Callback<AccountState> &done) {
  _external->lib()
      .request(TLGetAccountState(tl_accountAddress(tl_string(address))))
      .done([=](const TLFullAccountState &result) { InvokeCallback(done, Parse(result)); })
      .fail([=](const TLError &error) { InvokeCallback(done, ErrorFromLib(error)); })
      .send();
}

void Wallet::requestTransactions(const QString &address, const TransactionId &lastId,
                                 const Callback<TransactionsSlice> &done) {
  _external->lib()
      .request(TLraw_GetTransactions(tl_inputKeyFake(), tl_accountAddress(tl_string(address)),
                                     tl_internal_transactionId(tl_int64(lastId.lt), tl_bytes(lastId.hash))))
      .done([=](const TLraw_Transactions &result) { InvokeCallback(done, Parse(result)); })
      .fail([=](const TLError &error) { InvokeCallback(done, ErrorFromLib(error)); })
      .send();
}

void Wallet::requestTokenStates(const CurrencyMap<TokenStateValue> &previousStates,
                                const Callback<CurrencyMap<TokenStateValue>> &done) const {
  if (previousStates.empty()) {
    return InvokeCallback(done, CurrencyMap<TokenStateValue>{});
  }

  struct StateContext {
    explicit StateContext(const CurrencyMap<TokenStateValue> &tokens,
                          const Callback<CurrencyMap<TokenStateValue>> &done)
        : done{done} {
      for (const auto &item : tokens) {
        requestedTokens.emplace(item.first);
      }
    }

    void notifySuccess(TokenState &&tokenState) {
      std::unique_lock lock{mutex};
      result.insert(std::make_pair(  //
          tokenState.token,          //
          TokenStateValue{.walletContractAddress = tokenState.walletContractAddress,
                          .rootOwnerAddress = tokenState.rootOwnerAddress,
                          .lastTransactions = tokenState.lastTransactions,
                          .balance = tokenState.balance}));
      checkComplete(tokenState.token);
    }

    void notifyError(const Symbol &symbol) {
      std::unique_lock lock{mutex};
      checkComplete(symbol);
    }

    void checkComplete(const Symbol &symbol) {
      requestedTokens.erase(symbol);
      if (requestedTokens.empty()) {
        InvokeCallback(done, std::move(result));
      }
    }

    std::unordered_set<Symbol> requestedTokens{};
    CurrencyMap<TokenStateValue> result;
    Callback<CurrencyMap<TokenStateValue>> done;
    std::shared_mutex mutex;
  };

  std::shared_ptr<StateContext> ctx{new StateContext{previousStates, done}};

  for (const auto &[symbol, token] : previousStates) {
    _external->lib()
        .request(TLGetAccountState(tl_accountAddress(tl_string(token.walletContractAddress))))
        .done([=, symbol = symbol, token = token](TLFullAccountState &&result) mutable {
          if (result.c_fullAccountState().vaccount_state().type() == id_uninited_accountState) {
            return ctx->notifySuccess(TokenState{.token = symbol,
                                                 .walletContractAddress = token.walletContractAddress,
                                                 .rootOwnerAddress = token.rootOwnerAddress,
                                                 .balance = 0});
          } else if (result.c_fullAccountState().vaccount_state().type() != id_raw_accountState) {
            return InvokeCallback(done, Error{Error::Type::TonLib, "Requested account is not a token wallet contract"});
          }

          const auto lastId = Parse(result.c_fullAccountState().vlast_transaction_id());

          auto getBalance = [=, result = std::forward<TLfullAccountState>(result)](
                                TransactionsSlice &&lastTransactions) mutable {
            const auto &info = result.c_fullAccountState();
            const auto &accountState = result.c_fullAccountState().vaccount_state().c_raw_accountState();

            _external->lib()
                .request(TLftabi_RunLocalCachedSplit(                                               //
                    tl_accountAddress(tl_string(token.walletContractAddress)),                      //
                    tl_int64(info.vlast_transaction_id().c_internal_transactionId().vlt().v + 10),  //
                    tl_int32(static_cast<int32>(info.vsync_utime().v)),                             //
                    info.vbalance(),                                                                //
                    accountState.vdata(),                                                           //
                    accountState.vcode(),                                                           //
                    TokenGetBalanceFunction(),                                                      //
                    tl_ftabi_functionCallExternal({}, {})))
                .done([=, result = std::move(result)](const TLftabi_tvmOutput &tvmResult) mutable {
                  const auto &output = tvmResult.c_ftabi_tvmOutput();
                  if (output.vsuccess().type() != id_boolTrue) {
                    return ctx->notifyError(symbol);
                  }

                  const auto &results = output.vvalues().v;
                  if (results.empty() || !IsBigInt(results[0])) {
                    //InvokeCallback(done, Error { Error::Type::TonLib, "failed to parse results" });
                    std::cout << "failed to parse results: " << results.size() << std::endl;
                    return ctx->notifyError(symbol);
                  }

                  const auto balance = UnpackUint128(results[0]);
                  ctx->notifySuccess(  //
                      TokenState{.token = symbol,
                                 .walletContractAddress = token.walletContractAddress,
                                 .rootOwnerAddress = token.rootOwnerAddress,
                                 .lastTransactions = std::forward<TransactionsSlice>(lastTransactions),
                                 .balance = balance});
                })
                .fail([=](const TLError &error) {
                  std::cout << "error in RootTokenContract.getDetails: " << error.c_error().vmessage().v.toStdString()
                            << std::endl;
                  ctx->notifyError(symbol);
                })
                .send();
          };

          if (lastId.lt == token.lastTransactions.previousId.lt) {
            return getBalance(std::move(token.lastTransactions));
          }
          _external->lib()
              .request(TLraw_GetTransactions(tl_inputKeyFake(),
                                             tl_accountAddress(tl_string(token.walletContractAddress)),
                                             tl_internal_transactionId(tl_int64(lastId.lt), tl_bytes(lastId.hash))))
              .done([getBalance = std::move(getBalance)](const TLraw_Transactions &result) mutable {
                getBalance(Parse(result));
              })
              .fail([=](const TLError &error) {
                // InvokeCallback(done, ErrorFromLib(error));
                std::cout << "Get last transactions: " << error.c_error().vmessage().v.toStdString() << std::endl;
                ctx->notifyError(symbol);
              })
              .send();
        })
        .fail([=, symbol = symbol](const TLError &error) {
          // InvokeCallback(done, Error{Error::Type::TonLib, "Failed to get token wallet state"});
          std::cout << "Failed to get account state: " << error.c_error().vmessage().v.toStdString() << std::endl;
          ctx->notifyError(symbol);
        })
        .send();
  }
}

void Wallet::requestDePoolParticipantInfo(const QByteArray &publicKey, const DePoolStatesMap &previousStates,
                                          const Callback<DePoolStatesMap> &done) const {
  if (previousStates.empty()) {
    return InvokeCallback(done, DePoolStatesMap{});
  }

  const auto walletAddress = getUsedAddress(publicKey);
  Assert(!walletAddress.isEmpty());

  struct StateContext {
    explicit StateContext(const DePoolStatesMap &dePools, const Callback<DePoolStatesMap> &done) : done{done} {
      for (const auto &item : dePools) {
        requestedDePools.emplace(item.first);
      }
    }

    void notifySuccess(const QString &address, DePoolParticipantState &&state) {
      std::unique_lock lock{mutex};
      result.insert(std::make_pair(address, state));
      checkComplete(address);
    }

    void notifyError(const QString &address) {
      std::unique_lock lock{mutex};
      checkComplete(address);
    }

    void checkComplete(const QString &address) {
      requestedDePools.erase(address);
      if (requestedDePools.empty()) {
        InvokeCallback(done, std::move(result));
      }
    }

    std::unordered_set<QString> requestedDePools{};
    DePoolStatesMap result;
    Callback<DePoolStatesMap> done;
    std::shared_mutex mutex;
  };

  std::shared_ptr<StateContext> ctx{new StateContext{previousStates, done}};

  for (const auto &[address, previousState] : previousStates) {
    _external->lib()
        .request(TLftabi_RunLocal(                                 //
            tl_accountAddress(tl_string(address)),                 //
            DePoolParticipantInfoFunction(previousState.version),  //
            tl_ftabi_functionCallExternal({},
                                          tl_vector(QVector<TLftabi_Value>{
                                              PackAddress(walletAddress),  // account
                                          }))))
        .done([=, address = address, previousState = previousState](const TLftabi_tvmOutput &tvmResult) {
          auto state = ParseDePoolParticipantState(previousState.version, tvmResult);
          if (state.has_value()) {
            ctx->notifySuccess(address, std::move(*state));
          } else {
            ctx->notifyError(address);
          }
        })
        .fail([=, address = address, previousState = previousState](const TLError &error) mutable {
          // ErrorFromLib(error)
          ctx->notifySuccess(address, std::move(previousState));
        })
        .send();
  }
}

void Wallet::requestMultisigStates(const MultisigStatesMap &previousStates, const Callback<MultisigStatesMap> &done) {
  if (previousStates.empty()) {
    return InvokeCallback(done, MultisigStatesMap{});
  }

  struct StateContext {
    explicit StateContext(const MultisigStatesMap &multisigs, const Callback<MultisigStatesMap> &done) : done{done} {
      for (const auto &item : multisigs) {
        requestedMultisigs.emplace(item.first);
      }
    }

    void notifySuccess(const QString &address, MultisigState &&state) {
      std::unique_lock lock{mutex};
      result.insert(std::make_pair(address, state));
      checkComplete(address);
    }

    void notifyError(const QString &address) {
      std::unique_lock lock{mutex};
      checkComplete(address);
    }

    void checkComplete(const QString &address) {
      requestedMultisigs.erase(address);
      if (requestedMultisigs.empty()) {
        InvokeCallback(done, std::move(result));
      }
    }

    std::unordered_set<QString> requestedMultisigs{};
    MultisigStatesMap result;
    Callback<MultisigStatesMap> done;
    std::shared_mutex mutex;
  };

  std::shared_ptr<StateContext> ctx{new StateContext{previousStates, done}};

  for (const auto &[address, previousState] : previousStates) {
    requestState(
        address, [=, address = address, previousState = previousState](Result<AccountState> accountState) mutable {
          if (!accountState.has_value()) {
            return ctx->notifySuccess(address, std::move(previousState));
          }

          const auto lastTransactionId = accountState->lastTransactionId;
          bool transactionsChanged = previousState.accountState.lastTransactionId != lastTransactionId;

          previousState.accountState = std::move(accountState.value());

          if (transactionsChanged) {
            requestTransactions(
                address, lastTransactionId,
                [=, previousState = std::move(previousState)](Result<TransactionsSlice> lastTransactions) mutable {
                  if (lastTransactions.has_value()) {
                    previousState.lastTransactions = std::move(lastTransactions.value());
                  }
                  ctx->notifySuccess(address, std::move(previousState));
                });
          } else {
            ctx->notifySuccess(address, std::move(previousState));
          }
        });
  }
}

void Wallet::requestNewMultisigAddress(MultisigVersion version, const QByteArray &publicKey,
                                       const Callback<MultisigPredeployInfo> &done) {
  auto initData = CreateMultisigInitData(version, publicKey);
  if (!initData.has_value()) {
    std::cout << initData.error().details.toStdString() << std::endl;
    return InvokeCallback(done, Error{Error::Type::TonLib, "Failed to compute init data"});
  }
  const auto rawContractAddress = QString{"0:"} + initData->hash.toHex();
  const auto packedAddress = ConvertIntoPacked(rawContractAddress);

  _external->lib()
      .request(TLGetAccountState(tl_accountAddress(tl_string(packedAddress))))
      .done([=](TLFullAccountState &&result) mutable {
        const auto &account = result.c_fullAccountState();
        if (account.vaccount_state().type() == id_uninited_accountState) {
          return InvokeCallback(  //
              done, MultisigPredeployInfo{.balance = account.vbalance().v,
                                          .initialInfo = MultisigInitialInfo{
                                              .address = packedAddress,
                                              .version = version,
                                              .publicKey = publicKey,
                                              .initState = std::move(initData->data),
                                          }});
        } else {
          std::cout << "Address: " << rawContractAddress.toStdString() << " " << account.vaccount_state().type()
                    << std::endl;
          return InvokeCallback(done, Error{Error::Type::TonLib, "Account already exists"});
        }
      })
      .fail([=](const TLError &error) {
        InvokeCallback(done, Error{Error::Type::TonLib, "Failed to get multisig wallet state"});
      })
      .send();
}

void Wallet::requestMultisigInfo(const QString &address, const Callback<MultisigInfo> &done) {
  const auto packedMultisigAddress = ConvertIntoPacked(address);

  constexpr auto error_account_not_found = "Requested account doesn't exist";
  constexpr auto error_invalid_contract = "Requested account is not a multisig contract";

  _external->lib()
      .request(TLGetAccountState(tl_accountAddress(tl_string(packedMultisigAddress))))
      .done([=](TLFullAccountState &&result) mutable {
        const auto &codeHash = result.c_fullAccountState().vcode_hash().v;
        const auto multisigVersion = GuessMultisigVersion(codeHash);

        if (result.c_fullAccountState().vaccount_state().type() == id_uninited_accountState) {
          return InvokeCallback(done, Error{Error::Type::TonLib, error_account_not_found});
        } else if (result.c_fullAccountState().vaccount_state().type() != id_raw_accountState ||
                   !multisigVersion.has_value()) {
          return InvokeCallback(done, Error{Error::Type::TonLib, error_invalid_contract});
        }

        const auto &info = result.c_fullAccountState();
        const auto &transactionLt = info.vlast_transaction_id().c_internal_transactionId().vlt().v;
        const auto &syncUtime = static_cast<int32>(info.vsync_utime().v);
        const auto &accountState = info.vaccount_state().c_raw_accountState();
        const auto &balance = info.vbalance();
        const auto &data = accountState.vdata();
        const auto &code = accountState.vcode();

        auto getCustodians = [=](MultisigInfo &&multisigInfo) {
          const auto &info = result.c_fullAccountState();
          const auto &accountState = result.c_fullAccountState().vaccount_state().c_raw_accountState();

          _external->lib()
              .request(TLftabi_RunLocalCachedSplit(                     //
                  tl_accountAddress(tl_string(packedMultisigAddress)),  //
                  tl_int64(transactionLt + 10),                         //
                  tl_int32(syncUtime),                                  //
                  balance,                                              //
                  data,                                                 //
                  code,                                                 //
                  MultisigGetCustodians(),                              //
                  tl_ftabi_functionCallExternal({}, {})))
              .done([=, info = std::forward<MultisigInfo>(multisigInfo)](const TLftabi_tvmOutput &tvmResult) mutable {
                const auto &output = tvmResult.c_ftabi_tvmOutput();
                if (output.vsuccess().type() != id_boolTrue) {
                  return InvokeCallback(done, ErrorFromLib(GenerateVmError(output.vexit_code())));
                }

                const auto &results = output.vvalues().v;
                const auto invalidAbiError = Error{Error::Type::TonLib, "Invalid Multisig.getParameters abi"};
                if (results.size() != 1 || results[0].type() != id_ftabi_valueArray) {
                  return InvokeCallback(done, invalidAbiError);
                }

                const auto custodians = results[0].c_ftabi_valueArray().vvalues().v;
                info.custodians.reserve(custodians.size());
                for (const auto custodian : custodians) {
                  if (custodian.type() != id_ftabi_valueTuple) {
                    return InvokeCallback(done, invalidAbiError);
                  }
                  const auto &tuple = custodian.c_ftabi_valueTuple().vvalues().v;
                  if (tuple.size() != 2 || !IsBigInt(tuple[1])) {
                    return InvokeCallback(done, invalidAbiError);
                  }

                  const auto publicKey = UnpackPubkey(tuple[1]);
                  info.custodians.push_back(PackPublicKey(publicKey));
                }

                InvokeCallback(done, info);
              })
              .fail([=](const TLError &error) {
                InvokeCallback(done, Error{Error::Type::TonLib, "Failed to get multisig custodians"});
              })
              .send();
        };

        _external->lib()
            .request(TLftabi_RunLocalCachedSplit(                     //
                tl_accountAddress(tl_string(packedMultisigAddress)),  //
                tl_int64(transactionLt + 10),                         //
                tl_int32(syncUtime),                                  //
                balance,                                              //
                data,                                                 //
                code,                                                 //
                MultisigGetParameters(*multisigVersion),              //
                tl_ftabi_functionCallExternal({}, {})))
            .done([=](const TLftabi_tvmOutput &tvmResult) mutable {
              const auto &output = tvmResult.c_ftabi_tvmOutput();
              if (output.vsuccess().type() != id_boolTrue) {
                return InvokeCallback(done, ErrorFromLib(GenerateVmError(output.vexit_code())));
              }

              const auto &results = output.vvalues().v;
              const auto invalidAbiError = Error{Error::Type::TonLib, "Invalid Multisig.getParameters abi"};
              if (results.size() < 5 || results[2].type() != id_ftabi_valueInt) {
                return InvokeCallback(done, invalidAbiError);
              }

              getCustodians(MultisigInfo{
                  .address = packedMultisigAddress,
                  .version = multisigVersion.value(),
                  .expirationTime = UnpackUint(results[2]),
              });
            })
            .fail([=](const TLError &error) {
              std::cout << error.c_error().vmessage().v.toStdString() << std::endl;
              InvokeCallback(done, Error{Error::Type::TonLib, "Failed to get multisig parameters"});
            })
            .send();
      })
      .fail([=](const TLError &error) {
        std::cout << error.c_error().vmessage().v.toStdString() << std::endl;
        InvokeCallback(done, Error{Error::Type::TonLib, "Failed to get multisig wallet state"});
      })
      .send();
}

void Wallet::decrypt(const QByteArray &publicKey, std::vector<Transaction> &&list,
                     const Callback<std::vector<Transaction>> &done) {
  const auto encrypted = CollectEncryptedTexts(list);
  if (encrypted.empty()) {
    return InvokeCallback(done, std::move(list));
  }
  const auto shared = std::make_shared<std::vector<Transaction>>(std::move(list));
  const auto password = _viewersPasswords[publicKey];
  const auto generation = password.generation;
  const auto fail = [=](const TLError &error) {
    handleInputKeyError(publicKey, generation, error, [=](Result<> result) {
      if (result) {
        decrypt(publicKey, std::move(*shared), done);
      } else {
        InvokeCallback(done, result.error());
      }
    });
  };
  if (password.bytes.isEmpty()) {
    fail(GenerateFakeIncorrectPasswordError());
    return;
  }
  _external->lib()
      .request(TLmsg_Decrypt(prepareInputKey(publicKey, password.bytes), MsgDataArrayFromEncrypted(encrypted)))
      .done([=](const TLmsg_DataDecryptedArray &result) {
        notifyPasswordGood(publicKey, generation);
        InvokeCallback(done, AddDecryptedTexts(std::move(*shared), encrypted, MsgDataArrayToDecrypted(result)));
      })
      .fail(fail)
      .send();
}

void Wallet::trySilentDecrypt(const QByteArray &publicKey, std::vector<Transaction> &&list,
                              const Callback<std::vector<Transaction>> &done) {
  const auto encrypted = CollectEncryptedTexts(list);
  if (encrypted.empty() || !_viewersPasswords.contains(publicKey)) {
    return InvokeCallback(done, std::move(list));
  }
  const auto shared = std::make_shared<std::vector<Transaction>>(std::move(list));
  const auto password = _viewersPasswords[publicKey];
  _external->lib()
      .request(TLmsg_Decrypt(prepareInputKey(publicKey, password.bytes), MsgDataArrayFromEncrypted(encrypted)))
      .done([=](const TLmsg_DataDecryptedArray &result) {
        InvokeCallback(done, AddDecryptedTexts(std::move(*shared), encrypted, MsgDataArrayToDecrypted(result)));
      })
      .fail([=](const TLError &error) { InvokeCallback(done, std::move(*shared)); })
      .send();
}

void Wallet::getWalletOwner(const QString &rootTokenContract, const QString &walletAddress,
                            const Callback<QString> &done) {
  {
    const auto &cache = _external->tokenOwnersCache();
    if (const auto groupIt = cache.find(rootTokenContract); groupIt != cache.end()) {
      const auto &group = groupIt->second.entries;
      if (const auto it = group.find(walletAddress); it != group.end()) {
        auto owner = it->second;
        return InvokeCallback(done, std::move(owner));
      }
    }
  }

  _external->lib()
      .request(TLftabi_RunLocal(                        //
          tl_accountAddress(tl_string(walletAddress)),  //
          TokenWalletGetDetailsFunction(),              //
          tl_ftabi_functionCallExternal({}, {})))
      .done([=](const TLftabi_tvmOutput &tvmResult) {
        const auto &output = tvmResult.c_ftabi_tvmOutput();
        if (output.vsuccess().type() != id_boolTrue) {
          return InvokeCallback(done, ErrorFromLib(GenerateVmError(output.vexit_code())));
        }

        const auto details = ParseTokenWalletContractDetails(output.vvalues());
        if (!details.has_value()) {
          return InvokeCallback(done, Ton::Error{Ton::Error::Type::TonLib, "Invalid TokenWallet.getDetails ABI"});
        }
        if (details->rootAddress != rootTokenContract) {
          return InvokeCallback(
              done, Ton::Error{Ton::Error::Type::TonLib, "Token wallet does not belong to this root token contract"});
        }
        const auto ownerAddress = details->ownerAddress;
        _external->updateTokenOwnersCache(rootTokenContract, walletAddress, ownerAddress,
                                          [=](const Result<> &) { InvokeCallback(done, ownerAddress); });
      })
      .fail([=](const TLError &error) { InvokeCallback(done, ErrorFromLib(error)); })
      .send();
}

void Wallet::getWalletOwners(const QString &rootTokenContract, const QSet<QString> &addresses,
                             const Fn<void(std::map<QString, QString> &&)> &done) {
  std::map<QString, QString> result;
  std::vector<QString> unknownOwners;

  {
    const auto &cache = _external->tokenOwnersCache();
    if (const auto groupIt = cache.find(rootTokenContract); groupIt != cache.end()) {
      const auto &group = groupIt->second.entries;
      for (const auto &wallet : addresses) {
        const auto it = group.find(wallet);
        if (it != group.end()) {
          result.emplace(std::piecewise_construct, std::forward_as_tuple(wallet), std::forward_as_tuple(it->second));
        } else {
          unknownOwners.emplace_back(wallet);
        }
      }
    } else {
      for (const auto &address : addresses) {
        unknownOwners.emplace_back(address);
      }
    }
  }

  if (unknownOwners.empty()) {
    return done(std::move(result));
  }

  class OwnersContext {
   public:
    using Result = std::map<QString, QString>;
    using Done = Fn<void(std::map<QString, QString> &&)>;

    OwnersContext(Result &&result, int targetCount, Done &&done)
        : _result{std::forward<Result>(result)}, _count{targetCount}, _done{std::forward<Done>(done)} {
    }

    void notifyFound(const QString &wallet, QString &&owner) {
      std::unique_lock<std::mutex> lock{_mutex};
      _result.emplace(std::piecewise_construct, std::forward_as_tuple(wallet),
                      std::forward_as_tuple(std::forward<QString>(owner)));
      checkFinished();
    }

    void notifyNotFound() {
      std::unique_lock<std::mutex> lock{_mutex};
      checkFinished();
    }

   private:
    void checkFinished() {
      if (--_count <= 0) {
        _done(std::move(_result));
      }
    }

    std::mutex _mutex;
    Result _result;
    int _count;
    Done _done;
  };

  const auto onOwnersLoaded = crl::guard(this, [=](OwnersContext::Result &&result) {
    const auto newItems = TokenOwnersCache{result};
    _external->updateTokenOwnersCache(  //
        rootTokenContract, newItems,
        crl::guard(this, [=, result = std::forward<OwnersContext::Result>(result)](const Result<> &) mutable {
          done(std::move(result));
        }));
  });

  auto context = std::make_shared<OwnersContext>(
      std::move(result), unknownOwners.size(),
      [=](OwnersContext::Result &&result) { onOwnersLoaded(std::forward<OwnersContext::Result>(result)); });

  for (const auto &walletAddress : unknownOwners) {
    _external->lib()
        .request(TLftabi_RunLocal(                        //
            tl_accountAddress(tl_string(walletAddress)),  //
            TokenWalletGetDetailsFunction(),              //
            tl_ftabi_functionCallExternal({}, {})))
        .done([=](const TLftabi_tvmOutput &tvmResult) {
          const auto &output = tvmResult.c_ftabi_tvmOutput();
          if (output.vsuccess().type() != id_boolTrue) {
            return context->notifyNotFound();
          }

          auto details = ParseTokenWalletContractDetails(output.vvalues());

          auto success = true;
          if (!details.has_value()) {
            std::cout << "Invalid TokenWallet.getDetails ABI";  // TODO: handle error?
            success = false;
          }
          if (success && details->rootAddress != rootTokenContract) {
            std::cout << "Token wallet does not belong to this root token contract";  // TODO: handle error?
            success = false;
          }

          if (success) {
            context->notifyFound(walletAddress, std::move(details->ownerAddress));
          } else {
            context->notifyNotFound();
          }
        })
        .fail([=](const TLError &error) {
          std::cout << "Failed to fetch wallet owner: " << error.c_error().vmessage().v.toStdString() << std::endl;
          context->notifyNotFound();
        })
        .send();
  }
}

void Wallet::getEthEventDetails(const QString &ethEventContract, const Callback<EthEventDetails> &done) {
  _external->lib()
      .request(TLGetAccountState(tl_accountAddress(tl_string(ethEventContract))))
      .done([=](TLFullAccountState &&result) mutable {
        if (result.c_fullAccountState().vaccount_state().type() == id_uninited_accountState) {
          return InvokeCallback(done, Error{Error::Type::TonLib, "Requested account doesn't exist"});
        } else if (result.c_fullAccountState().vaccount_state().type() != id_raw_accountState) {
          return InvokeCallback(done, Error{Error::Type::TonLib, "Requested account is not a token wallet contract"});
        }

        const auto &info = result.c_fullAccountState();
        const auto &transactionLt = info.vlast_transaction_id().c_internal_transactionId().vlt().v;
        const auto &syncUtime = static_cast<int32>(info.vsync_utime().v);
        const auto &accountState = info.vaccount_state().c_raw_accountState();
        const auto &balance = info.vbalance();
        const auto &data = accountState.vdata();
        const auto &code = accountState.vcode();

        auto getDecodedData = [=](EthEventDetails &&ethEventDetails) {
          const auto &info = result.c_fullAccountState();
          const auto &accountState = result.c_fullAccountState().vaccount_state().c_raw_accountState();

          _external->lib()
              .request(TLftabi_RunLocalCachedSplit(                //
                  tl_accountAddress(tl_string(ethEventContract)),  //
                  tl_int64(transactionLt + 10),                    //
                  tl_int32(syncUtime),                             //
                  balance,                                         //
                  data,                                            //
                  code,                                            //
                  EthEventGetDecodedDataFunction(),                //
                  tl_ftabi_functionCallExternal({}, {})))
              .done([=](const TLftabi_tvmOutput &tvmResult) mutable {
                const auto &output = tvmResult.c_ftabi_tvmOutput();
                if (output.vsuccess().type() != id_boolTrue) {
                  return InvokeCallback(done, ErrorFromLib(GenerateVmError(output.vexit_code())));
                }

                const auto &results = output.vvalues().v;
                if (results.size() > 1 && IsAddress(results[0])) {
                  ethEventDetails.rootTokenContract = UnpackAddress(results[0]);
                }
                InvokeCallback(done, ethEventDetails);
              })
              .fail([=](const TLError &error) {
                std::cout << "error in EthEvent.getDecodedData: " << error.c_error().vmessage().v.toStdString()
                          << std::endl;
                InvokeCallback(done, ethEventDetails);
              })
              .send();
        };

        _external->lib()
            .request(TLftabi_RunLocalCachedSplit(                //
                tl_accountAddress(tl_string(ethEventContract)),  //
                tl_int64(transactionLt + 10),                    //
                tl_int32(syncUtime),                             //
                balance,                                         //
                data,                                            //
                code,                                            //
                EthEventGetDetailsFunction(),                    //
                tl_ftabi_functionCallExternal({}, {})))
            .done([=](const TLftabi_tvmOutput &tvmResult) mutable {
              const auto &output = tvmResult.c_ftabi_tvmOutput();
              if (output.vsuccess().type() != id_boolTrue) {
                return InvokeCallback(done, ErrorFromLib(GenerateVmError(output.vexit_code())));
              }

              const auto &results = output.vvalues().v;
              const auto invalidAbiError = Error{Error::Type::TonLib, "Invalid EthEvent.getDetails abi"};
              if (results.size() != 4) {
                return InvokeCallback(done, invalidAbiError);
              }
              auto status = ParseEthEventStatus(results[1]);
              if (!status.has_value() || results[0].type() != id_ftabi_valueTuple ||
                  results[2].type() != id_ftabi_valueArray || results[3].type() != id_ftabi_valueArray) {
                return InvokeCallback(done, invalidAbiError);
              }
              const auto &initData = results[0].c_ftabi_valueTuple().vvalues().v;
              if (initData.size() < 10 || !IsInt(initData[6]) || !IsInt(initData[7])) {
                return InvokeCallback(done, invalidAbiError);
              }
              getDecodedData(EthEventDetails{
                  .status = *status,
                  .requiredConfirmationCount = static_cast<uint16>(UnpackUint(initData[6])),
                  .requiredRejectionCount = static_cast<uint16>(UnpackUint(initData[7])),
                  .confirmationCount = static_cast<uint16>(results[2].c_ftabi_valueArray().vvalues().v.size()),
                  .rejectionCount = static_cast<uint16>(results[3].c_ftabi_valueArray().vvalues().v.size()),
              });
            })
            .fail([=](const TLError &error) {
              InvokeCallback(done, Error{Error::Type::TonLib, "Failed to get EthEvent details"});
            })
            .send();
      })
      .fail([=](const TLError &error) {
        InvokeCallback(done, Error{Error::Type::TonLib, "Failed to get token wallet state"});
      })
      .send();
}

void Wallet::getTonEventDetails(const QString &tonEventContract, const Callback<TonEventDetails> &done) {
  _external->lib()
      .request(TLGetAccountState(tl_accountAddress(tl_string(tonEventContract))))
      .done([=](TLFullAccountState &&result) mutable {
        if (result.c_fullAccountState().vaccount_state().type() == id_uninited_accountState) {
          return InvokeCallback(done, Error{Error::Type::TonLib, "Requested account doesn't exist"});
        } else if (result.c_fullAccountState().vaccount_state().type() != id_raw_accountState) {
          return InvokeCallback(done, Error{Error::Type::TonLib, "Requested account is not a token wallet contract"});
        }

        const auto &info = result.c_fullAccountState();
        const auto &transactionLt = info.vlast_transaction_id().c_internal_transactionId().vlt().v;
        const auto &syncUtime = static_cast<int32>(info.vsync_utime().v);
        const auto &accountState = info.vaccount_state().c_raw_accountState();
        const auto &balance = info.vbalance();
        const auto &data = accountState.vdata();
        const auto &code = accountState.vcode();

        auto getDecodedData = [=](TonEventDetails &&tonEventDetails) {
          const auto &info = result.c_fullAccountState();
          const auto &accountState = result.c_fullAccountState().vaccount_state().c_raw_accountState();

          _external->lib()
              .request(TLftabi_RunLocalCachedSplit(                //
                  tl_accountAddress(tl_string(tonEventContract)),  //
                  tl_int64(transactionLt + 10),                    //
                  tl_int32(syncUtime),                             //
                  balance,                                         //
                  data,                                            //
                  code,                                            //
                  TonEventGetDecodedDataFunction(),                //
                  tl_ftabi_functionCallExternal({}, {})))
              .done([=](const TLftabi_tvmOutput &tvmResult) mutable {
                const auto &output = tvmResult.c_ftabi_tvmOutput();
                if (output.vsuccess().type() != id_boolTrue) {
                  return InvokeCallback(done, ErrorFromLib(GenerateVmError(output.vexit_code())));
                }

                const auto &results = output.vvalues().v;
                if (results.size() > 1 && IsAddress(results[0])) {
                  tonEventDetails.rootTokenContract = UnpackAddress(results[0]);
                }
                InvokeCallback(done, tonEventDetails);
              })
              .fail([=](const TLError &error) {
                std::cout << "error in TonEvent.getDecodedData: " << error.c_error().vmessage().v.toStdString()
                          << std::endl;
                InvokeCallback(done, tonEventDetails);
              })
              .send();
        };

        _external->lib()
            .request(TLftabi_RunLocalCachedSplit(                //
                tl_accountAddress(tl_string(tonEventContract)),  //
                tl_int64(transactionLt + 10),                    //
                tl_int32(syncUtime),                             //
                balance,                                         //
                data,                                            //
                code,                                            //
                TonEventGetDetailsFunction(),                    //
                tl_ftabi_functionCallExternal({}, {})))
            .done([=](const TLftabi_tvmOutput &tvmResult) mutable {
              const auto &output = tvmResult.c_ftabi_tvmOutput();
              if (output.vsuccess().type() != id_boolTrue) {
                return InvokeCallback(done, ErrorFromLib(GenerateVmError(output.vexit_code())));
              }

              const auto &results = output.vvalues().v;
              const auto invalidAbiError = Error{Error::Type::TonLib, "Invalid TonEvent.getDetails abi"};
              if (results.size() != 5) {
                return InvokeCallback(done, invalidAbiError);
              }
              auto status = ParseTonEventStatus(results[1]);
              if (!status.has_value() || results[0].type() != id_ftabi_valueTuple ||
                  results[2].type() != id_ftabi_valueArray || results[3].type() != id_ftabi_valueArray) {
                return InvokeCallback(done, invalidAbiError);
              }
              const auto &initData = results[0].c_ftabi_valueTuple().vvalues().v;
              if (initData.size() < 9 || !IsInt(initData[6]) || !IsInt(initData[7])) {
                return InvokeCallback(done, invalidAbiError);
              }
              getDecodedData(TonEventDetails{
                  .status = *status,
                  .requiredConfirmationCount = static_cast<uint16>(UnpackUint(initData[6])),
                  .requiredRejectionCount = static_cast<uint16>(UnpackUint(initData[7])),
                  .confirmationCount = static_cast<uint16>(results[2].c_ftabi_valueArray().vvalues().v.size()),
                  .rejectionCount = static_cast<uint16>(results[3].c_ftabi_valueArray().vvalues().v.size()),
              });
            })
            .fail([=](const TLError &error) {
              InvokeCallback(done, Error{Error::Type::TonLib, "Failed to get TonEvent details"});
            })
            .send();
      })
      .fail([=](const TLError &error) {
        InvokeCallback(done, Error{Error::Type::TonLib, "Failed to get token wallet state"});
      })
      .send();
}

void Wallet::getRootTokenContractDetails(const QString &rootTokenContract,
                                         const Callback<RootTokenContractDetails> &done) {
  _external->lib()
      .request(TLftabi_RunLocal(                            //
          tl_accountAddress(tl_string(rootTokenContract)),  //
          RootTokenGetDetailsFunction(),                    //
          tl_ftabi_functionCallExternal({}, {})))
      .done([=](const TLftabi_tvmOutput &tvmResult) {
        const auto &output = tvmResult.c_ftabi_tvmOutput();
        if (output.vsuccess().type() != id_boolTrue) {
          return InvokeCallback(done, ErrorFromLib(GenerateVmError(output.vexit_code())));
        }

        auto details = ParseRootTokenContractDetails(output.vvalues());
        if (details.has_value()) {
          InvokeCallback(done, *details);
        } else {
          InvokeCallback(done, Error{Error::Type::TonLib, "Invalid RootTokenContract.getDetails ABI"});
        }
      })
      .fail([=](const TLError &error) { InvokeCallback(done, ErrorFromLib(error)); })
      .send();
}

void Wallet::handleInputKeyError(const QByteArray &publicKey, int generation, const TLerror &error, Callback<> done) {
  const auto parsed = ErrorFromLib(error);
  if (IsIncorrectPasswordError(parsed) && ranges::contains(_list->entries, publicKey, &WalletList::Entry::publicKey)) {
    if (_viewersPasswords.contains(publicKey) && _viewersPasswords[publicKey].generation == generation) {
      _viewersPasswords[publicKey].expires = 0;
      _viewersPasswordsWaiters[publicKey].emplace_back(done);
      _updates.fire({DecryptPasswordNeeded{publicKey, generation}});
    } else {
      InvokeCallback(done);
    }
  } else {
    notifyPasswordGood(publicKey, generation);
    InvokeCallback(done, parsed);
  }
}

void Wallet::notifyPasswordGood(const QByteArray &publicKey, int generation) {
  if (_viewersPasswords.contains(publicKey) && !_viewersPasswords[publicKey].expires) {
    const auto expires = crl::now() + kViewersPasswordExpires;
    _viewersPasswords[publicKey].expires = expires;
    if (!_viewersPasswordsExpireTimer.isActive()) {
      _viewersPasswordsExpireTimer.callOnce(kViewersPasswordExpires);
    }
  }
  _updates.fire({DecryptPasswordGood{generation}});
}

std::unique_ptr<AccountViewer> Wallet::createAccountViewer(const QByteArray &publicKey, const QString &address) {
  return _accountViewers->createAccountViewer(publicKey, address);
}

void Wallet::updateViewersPassword(const QByteArray &publicKey, const QByteArray &password) {
  if (password.isEmpty()) {
    _viewersPasswords.remove(publicKey);
    _viewersPasswordsWaiters.remove(publicKey);
    return;
  }
  auto &data = _viewersPasswords[publicKey];
  data.bytes = password;
  ++data.generation;
  if (const auto list = _viewersPasswordsWaiters.take(publicKey)) {
    for (const auto &callback : *list) {
      InvokeCallback(callback);
    }
  }
}

void Wallet::checkPasswordsExpiration() {
  const auto now = crl::now();
  auto next = crl::time(0);
  for (auto i = _viewersPasswords.begin(); i != _viewersPasswords.end();) {
    const auto expires = i->second.expires;
    if (!expires) {
      ++i;
    } else if (expires <= now) {
      _viewersPasswordsWaiters.remove(i->first);
      i = _viewersPasswords.erase(i);
    } else {
      if (!next || next > expires) {
        next = expires;
      }
      ++i;
    }
  }
  if (next) {
    _viewersPasswordsExpireTimer.callOnce(next - now);
  }
}

void Wallet::loadWebResource(const QString &url, Callback<QByteArray> done) {
  if (!_webLoader) {
    _webLoader = std::make_unique<WebLoader>([=] { _webLoader = nullptr; });
  }
  _webLoader->load(url, std::move(done));
}

Fn<void(Update)> Wallet::generateUpdatesCallback() {
  return [=](Update update) {
    if (const auto sync = std::get_if<SyncState>(&update.data)) {
      if (*sync == _lastSyncStateUpdate) {
        return;
      }
      _lastSyncStateUpdate = *sync;
    } else if (const auto upgrade = std::get_if<ConfigUpgrade>(&update.data)) {
      if (*upgrade == ConfigUpgrade::TestnetToMainnet) {
        _switchedToMain = true;
      }
    }
    _updates.fire(std::move(update));
  };
}

void Wallet::checkLocalTime(BlockchainTime time) {
  if (_localTimeSyncer) {
    _localTimeSyncer->updateBlockchainTime(time);
    return;
  } else if (LocalTimeSyncer::IsLocalTimeBad(time)) {
    _localTimeSyncer = std::make_unique<LocalTimeSyncer>(time, &_external->lib(), [=] { _localTimeSyncer = nullptr; });
  }
}

auto Wallet::makeSendCallback(const Callback<> &done) -> std::function<void(int64)> {
  return [this, done = done](int64 id) {
    _external->lib()
        .request(TLquery_Send(tl_int53(id)))
        .done([=] { InvokeCallback(done); })
        .fail([=](const TLError &error) { InvokeCallback(done, ErrorFromLib(error)); })
        .send();
  };
}

auto Wallet::makeEstimateFeesCallback(const Callback<TransactionCheckResult> &done) -> std::function<void(int64)> {
  return [this, done = std::move(done)](int64 id) {
    _external->lib()
        .request(TLquery_EstimateFees(tl_int53(id), tl_boolTrue()))
        .done([=](const TLquery_Fees &result) {
          _external->lib().request(TLquery_Forget(tl_int53(id))).send();
          InvokeCallback(done, Parse(result));
        })
        .fail([=](const TLError &error) { InvokeCallback(done, ErrorFromLib(error)); })
        .send();
  };
}

void Wallet::checkTransactionFees(const QString &sender, const QString &recipient, const TLmsg_Data &body,
                                  int64 realAmount, int timeout, bool allowSendToUninited,
                                  const Callback<TransactionCheckResult> &done) {
  const auto check = makeEstimateFeesCallback(done);

  _external->lib()
      .request(TLCreateQuery(
          tl_inputKeyFake(), tl_accountAddress(tl_string(sender)), tl_int32(timeout),
          tl_actionMsg(tl_vector(1, tl_msg_message(tl_accountAddress(tl_string(recipient)), tl_string(),
                                                   tl_int64(realAmount), body, tl_int32(kDefaultMessageFlags))),
                       tl_from(allowSendToUninited)),
          tl_raw_initialAccountState(tl_bytes(), tl_bytes())  // doesn't matter
          ))
      .done([=](const TLquery_Info &result) { result.match([&](const TLDquery_info &data) { check(data.vid().v); }); })
      .fail([=](const TLError &error) { InvokeCallback(done, ErrorFromLib(error)); })
      .send();
}

void Wallet::sendMessage(const QByteArray &publicKey, const QByteArray &password, const QString &sender,
                         const QString &recipient, const tl::boxed<Ton::details::TLmsg_data> &body, int64 realAmount,
                         int timeout, bool allowSendToUninited, const Callback<PendingTransaction> &ready,
                         const Callback<> &done) {
  sendMessage(publicKey, password, sender, recipient, body, realAmount, timeout, allowSendToUninited, QString{}, ready,
              done);
}

void Wallet::sendMessage(const QByteArray &publicKey, const QByteArray &password, const QString &sender,
                         const QString &recipient, const tl::boxed<Ton::details::TLmsg_data> &body, int64 realAmount,
                         int timeout, bool allowSendToUninited, const QString &comment,
                         const Callback<PendingTransaction> &ready, const Callback<> &done) {
  const auto send = makeSendCallback(done);

  _external->lib()
      .request(TLCreateQuery(
          prepareInputKey(publicKey, password), tl_accountAddress(tl_string(sender)), tl_int32(timeout),
          tl_actionMsg(tl_vector(1, tl_msg_message(tl_accountAddress(tl_string(recipient)), tl_string(),
                                                   tl_int64(realAmount), body, tl_int32(kDefaultMessageFlags))),
                       tl_from(allowSendToUninited)),
          tl_raw_initialAccountState(tl_bytes(), tl_bytes())  // doesn't matter
          ))
      .done([=, ready = ready](const TLquery_Info &result) {
        result.match([&](const TLDquery_info &data) {
          const auto weak = base::make_weak(this);
          auto pending = Parse(result, sender,
                               TransactionToSend{.amount = realAmount,
                                                 .recipient = recipient,
                                                 .timeout = timeout,
                                                 .allowSendToUninited = allowSendToUninited});
          _accountViewers->addPendingTransaction(pending);
          if (!weak) {
            return;
          }
          InvokeCallback(ready, std::move(pending));
          if (!weak) {
            return;
          }
          send(data.vid().v);
        });
      })
      .fail([=, ready = ready](const TLError &error) { InvokeCallback(ready, ErrorFromLib(error)); })
      .send();
}

void Wallet::sendExternalMessage(const QString &sender, const QString &address, int timeout,
                                 const QByteArray &initState, const QByteArray &body,
                                 const Callback<PendingTransaction> &ready, const Callback<> &done) {
  const auto send = makeSendCallback(done);

  _external->lib()
      .request(TLraw_CreateQueryTvc(tl_accountAddress(tl_string(address)), tl_int32(timeout), tl_bytes(initState),
                                    tl_bytes(body)))
      .done([=, ready = ready](const TLquery_Info &result) {
        result.match([&](const TLDquery_info &data) {
          const auto weak = base::make_weak(this);
          auto pending = Parse(result, address,
                               TransactionToSend{
                                   .amount = 0,
                                   .recipient = address,
                                   .timeout = 0,
                                   .allowSendToUninited = true,
                               });
          _accountViewers->addMsigPendingTransaction(sender, address, pending);
          if (!weak) {
            return;
          }
          InvokeCallback(ready, std::move(pending));
          if (!weak) {
            return;
          }
          send(data.vid().v);
        });
      })
      .fail([=, ready = ready](const TLError &error) { InvokeCallback(ready, ErrorFromLib(error)); })
      .send();
}

}  // namespace Ton
