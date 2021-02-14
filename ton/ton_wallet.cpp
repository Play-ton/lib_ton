// This file is part of Desktop App Toolkit,
// a set of libraries for developing nice desktop applications.
//
// For license and copyright information please follow this link:
// https://github.com/desktop-app/legal/blob/master/LEGAL
//
#include "ton/ton_wallet.h"

#include "ton/details/ton_account_viewers.h"
#include "ton/details/ton_request_sender.h"
#include "ton/details/ton_key_creator.h"
#include "ton/details/ton_key_destroyer.h"
#include "ton/details/ton_password_changer.h"
#include "ton/details/ton_external.h"
#include "ton/details/ton_parse_state.h"
#include "ton/details/ton_web_loader.h"
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

constexpr auto kEthereumAddressByteCount = 20;

[[nodiscard]] TLError GenerateFakeIncorrectPasswordError() {
  return tl_error(tl_int32(0), tl_string("KEY_DECRYPT"));
}

[[nodiscard]] TLError GenerateInvalidAbiError() {
  return tl_error(tl_int32(500), tl_string("INVALID_ABI"));
}

[[nodiscard]] TLftabi_Value PackPubKey() {
  return tl_ftabi_valueInt(tl_ftabi_paramUint(tl_int32(256)), tl_int64(0));
}

[[nodiscard]] int128 UnpackUint128(const TLftabi_Value &value) {
  return value.match([](const TLDftabi_valueInt &value) { return int128{value.vvalue().v}; },
                     [](const TLDftabi_valueBigInt &value) { return BytesBEToInt128(value.vvalue().v); },
                     [](auto &&) {
                       Unexpected("ftabi value");
                       return int128{};
                     });
}

[[nodiscard]] TLftabi_Value PackUint128(int64 value) {
  return tl_ftabi_valueInt(tl_ftabi_paramUint(tl_int32(128)), tl_int64(value));
}

[[nodiscard]] TLftabi_Value PackUint128(const int128 &value) {
  return tl_ftabi_valueBigInt(tl_ftabi_paramUint(tl_int32(128)), tl_bytes(Int128ToBytesBE(value)));
}

[[nodiscard]] TLftabi_Value PackUint128() {
  return tl_ftabi_valueInt(tl_ftabi_paramUint(tl_int32(128)), tl_int64(0));
}

[[nodiscard]] int64 UnpackUint(const TLftabi_Value &value) {
  return value.c_ftabi_valueInt().vvalue().v;
}

[[nodiscard]] QString UnpackAddress(const TLftabi_Value &value) {
  return value.c_ftabi_valueAddress().vvalue().c_accountAddress().vaccount_address().v;
}

[[nodiscard]] TLftabi_Value PackAddress(const QString &value) {
  return tl_ftabi_valueAddress(tl_ftabi_paramAddress(), tl_accountAddress((tl_string(value))));
}

[[nodiscard]] TLftabi_Value PackCell(const TLtvm_Cell &value) {
  return tl_ftabi_valueCell(tl_ftabi_paramCell(), value);
}

[[nodiscard]] bool UnpackBool(const TLftabi_Value &value) {
  return value.c_ftabi_valueBool().vvalue().type() == id_boolTrue;
}

[[nodiscard]] QByteArray UnpackBytes(const TLftabi_Value &value) {
  return value.c_ftabi_valueBytes().vvalue().v;
}

bool IsAddress(const TLftabi_Value &value) {
  return value.type() == id_ftabi_valueAddress;
}

bool IsInt(const TLftabi_Value &value) {
  return value.type() == id_ftabi_valueInt;
}

bool IsBigInt(const TLftabi_Value &value) {
  return IsInt(value) || value.type() == id_ftabi_valueBigInt;
}

bool IsBool(const TLftabi_Value &value) {
  return value.type() == id_ftabi_valueBool;
}

bool IsCell(const TLftabi_Value &value) {
  return value.type() == id_ftabi_valueCell;
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

[[nodiscard]] std::map<int64, InvestParams> parseInvestParamsMap(const TLDftabi_valueMap &map) {
  std::map<int64, InvestParams> result;
  for (const auto &item : map.vvalues().v) {
    const auto key = UnpackUint(item.c_ftabi_valueMapItem().vkey());
    const auto values = item.c_ftabi_valueMapItem().vvalue().c_ftabi_valueTuple().vvalues().v;

    result.emplace(std::make_pair(key, InvestParams{
                                           .remainingAmount = UnpackUint(values[0]),
                                           .lastWithdrawalTime = UnpackUint(values[1]),
                                           .withdrawalPeriod = static_cast<int32>(UnpackUint(values[2])),
                                           .withdrawalValue = UnpackUint(values[3]),
                                           .owner = UnpackAddress(values[4]),
                                       }));
  }
  return result;
}

TLftabi_Function EthEventStatusChangedNotification() {
  static std::optional<TLftabi_function> function;
  if (!function.has_value()) {
    const auto createdFunction =
        RequestSender::Execute(TLftabi_CreateFunction(tl_string("notifyEthereumEventStatusChanged"), {},
                                                      tl_vector(QVector<TLftabi_Param>{
                                                          tl_ftabi_paramUint(tl_int32(8))  // status
                                                      }),
                                                      {}));
    Expects(createdFunction.has_value());
    function = createdFunction.value();
  }
  return *function;
}

TLftabi_Function TonEventStatusChangedNotification() {
  static std::optional<TLftabi_function> function;
  if (!function.has_value()) {
    const auto createdFunction =
        RequestSender::Execute(TLftabi_CreateFunction(tl_string("notifyTonEventStatusChanged"), {},
                                                      tl_vector(QVector<TLftabi_Param>{
                                                          tl_ftabi_paramUint(tl_int32(8))  // status
                                                      }),
                                                      {}));
    Expects(createdFunction.has_value());
    function = createdFunction.value();
  }
  return *function;
}

TLftabi_Function TokenWalletDeployedNotification() {
  static std::optional<TLftabi_function> function;
  if (!function.has_value()) {
    const auto createdFunction = RequestSender::Execute(
        TLftabi_CreateFunction(tl_string("notifyWalletDeployed"),
                               tl_vector(QVector<TLftabi_namedParam>{
                                   tl_ftabi_namedParam(tl_string("time"), tl_ftabi_paramTime()),
                                   tl_ftabi_namedParam(tl_string("expire"), tl_ftabi_paramExpire()),
                               }),
                               tl_vector(QVector<TLftabi_Param>{tl_ftabi_paramAddress()}), {}));
    Expects(createdFunction.has_value());
    function = createdFunction.value();
  }
  return *function;
}

TLftabi_Function TokenWalletGetDetailsFunction() {
  static std::optional<TLftabi_function> function;
  if (!function.has_value()) {
    const auto createdFunction = RequestSender::Execute(
        TLftabi_CreateFunction(tl_string("getDetails"),
                               tl_vector(QVector<TLftabi_namedParam>{
                                   tl_ftabi_namedParam(tl_string("time"), tl_ftabi_paramTime()),
                                   tl_ftabi_namedParam(tl_string("expire"), tl_ftabi_paramExpire()),
                               }),
                               {},
                               tl_vector(QVector<TLftabi_Param>{tl_ftabi_paramTuple(tl_vector(QVector<TLftabi_Param>{
                                   tl_ftabi_paramAddress(),            // root_address
                                   tl_ftabi_paramCell(),               // code
                                   tl_ftabi_paramUint(tl_int32(256)),  // wallet_public_key
                                   tl_ftabi_paramAddress(),            // owner_address
                                   tl_ftabi_paramUint(tl_int32(128)),  // balance
                               }))})));
    Expects(createdFunction.has_value());
    function = createdFunction.value();
  }
  return *function;
}

TLftabi_Function RootTokenGetDetailsFunction() {
  static std::optional<TLftabi_function> function;
  if (!function.has_value()) {
    const auto createdFunction = RequestSender::Execute(
        TLftabi_CreateFunction(tl_string("getDetails"),
                               tl_vector(QVector<TLftabi_namedParam>{
                                   tl_ftabi_namedParam(tl_string("time"), tl_ftabi_paramTime()),
                                   tl_ftabi_namedParam(tl_string("expire"), tl_ftabi_paramExpire()),
                               }),
                               {},
                               tl_vector(QVector<TLftabi_Param>{tl_ftabi_paramTuple(tl_vector(QVector<TLftabi_Param>{
                                   tl_ftabi_paramBytes(),              // name
                                   tl_ftabi_paramBytes(),              // symbol
                                   tl_ftabi_paramUint(tl_int32(8)),    // decimals
                                   tl_ftabi_paramCell(),               // wallet code
                                   tl_ftabi_paramUint(tl_int32(256)),  // root_public_key
                                   tl_ftabi_paramAddress(),            // root_owner_address
                                   tl_ftabi_paramUint(tl_int32(128)),  // total_supply
                                   tl_ftabi_paramUint(tl_int32(128)),  // start_gas_balance
                               }))})));
    Expects(createdFunction.has_value());
    function = createdFunction.value();
  }
  return *function;
}

TLftabi_Function RootTokenGetWalletAddressFunction() {
  static std::optional<TLftabi_function> function;
  if (!function.has_value()) {
    const auto createdFunction = RequestSender::Execute(
        TLftabi_CreateFunction(tl_string("getWalletAddress"),
                               tl_vector(QVector<TLftabi_namedParam>{
                                   tl_ftabi_namedParam(tl_string("time"), tl_ftabi_paramTime()),
                                   tl_ftabi_namedParam(tl_string("expire"), tl_ftabi_paramExpire()),
                               }),
                               tl_vector(QVector<TLftabi_Param>{
                                   tl_ftabi_paramUint(tl_int32(256)),  // wallet_public_key
                                   tl_ftabi_paramAddress(),            // owner_address
                               }),
                               tl_vector(QVector<TLftabi_Param>{tl_ftabi_paramAddress()})));
    Expects(createdFunction.has_value());
    function = createdFunction.value();
  }
  return *function;
}

TLftabi_Function RootTokenDeployWalletFunction() {
  static std::optional<TLftabi_function> function;
  if (!function.has_value()) {
    const auto createdFunction = RequestSender::Execute(
        TLftabi_CreateFunction(tl_string("deployEmptyWallet"),
                               tl_vector(QVector<TLftabi_namedParam>{
                                   tl_ftabi_namedParam(tl_string("time"), tl_ftabi_paramTime()),
                                   tl_ftabi_namedParam(tl_string("expire"), tl_ftabi_paramExpire()),
                               }),
                               tl_vector(QVector<TLftabi_Param>{
                                   tl_ftabi_paramUint(tl_int32(128)),  // grams
                                   tl_ftabi_paramUint(tl_int32(256)),  // wallet_public_key
                                   tl_ftabi_paramAddress(),            // owner_address
                                   tl_ftabi_paramAddress(),            // gas_back_address
                               }),
                               {}));
    Expects(createdFunction.has_value());
    function = createdFunction.value();
  }
  return *function;
}

TLftabi_Function ExecuteProxyCallbackFunction() {
  static std::optional<TLftabi_function> function;
  if (!function.has_value()) {
    const auto createdFunction =
        RequestSender::Execute(TLftabi_CreateFunction(tl_string("executeProxyCallback"), {}, {}, {}));
    Expects(createdFunction.has_value());
    function = createdFunction.value();
  }
  return *function;
}

TLftabi_Function TokenGetBalanceFunction() {
  static std::optional<TLftabi_function> function;
  if (!function.has_value()) {
    const auto createdFunction = RequestSender::Execute(
        TLftabi_CreateFunction(tl_string("balance"),
                               tl_vector(QVector<TLftabi_namedParam>{
                                   tl_ftabi_namedParam(tl_string("time"), tl_ftabi_paramTime()),
                                   tl_ftabi_namedParam(tl_string("expire"), tl_ftabi_paramExpire()),
                               }),
                               {}, tl_vector(QVector<TLftabi_Param>{tl_ftabi_paramUint(tl_int32(128))})));
    Expects(createdFunction.has_value());
    function = createdFunction.value();
  }
  return *function;
}

TLftabi_Function TokenAcceptFunction() {
  static std::optional<TLftabi_function> function;
  if (!function.has_value()) {
    const auto createdFunction = RequestSender::Execute(
        TLftabi_CreateFunction(tl_string("accept"),
                               tl_vector(QVector<TLftabi_namedParam>{
                                   tl_ftabi_namedParam(tl_string("time"), tl_ftabi_paramTime()),
                                   tl_ftabi_namedParam(tl_string("expire"), tl_ftabi_paramExpire()),
                               }),
                               tl_vector(QVector<TLftabi_Param>{
                                   tl_ftabi_paramUint(tl_int32(128)),  // tokens
                               }),
                               {}));
    Expects(createdFunction.has_value());
    function = createdFunction.value();
  }
  return *function;
}

TLftabi_Function TokenTransferFunction() {
  static std::optional<TLftabi_function> function;
  if (!function.has_value()) {
    const auto createdFunction = RequestSender::Execute(
        TLftabi_CreateFunction(tl_string("transfer"),
                               tl_vector(QVector<TLftabi_namedParam>{
                                   tl_ftabi_namedParam(tl_string("time"), tl_ftabi_paramTime()),
                                   tl_ftabi_namedParam(tl_string("expire"), tl_ftabi_paramExpire()),
                               }),
                               tl_vector(QVector<TLftabi_Param>{
                                   tl_ftabi_paramAddress(),            // to
                                   tl_ftabi_paramUint(tl_int32(128)),  // tokens
                                   tl_ftabi_paramUint(tl_int32(128))   // grams
                               }),
                               {}));
    Expects(createdFunction.has_value());
    function = createdFunction.value();
  }
  return *function;
}

TLftabi_Function TokenTransferToOwnerFunction() {
  static std::optional<TLftabi_function> function;
  if (!function.has_value()) {
    const auto createdFunction = RequestSender::Execute(
        TLftabi_CreateFunction(tl_string("transferToRecipient"),
                               tl_vector(QVector<TLftabi_namedParam>{
                                   tl_ftabi_namedParam(tl_string("time"), tl_ftabi_paramTime()),
                                   tl_ftabi_namedParam(tl_string("expire"), tl_ftabi_paramExpire()),
                               }),
                               tl_vector(QVector<TLftabi_Param>{
                                   tl_ftabi_paramUint(tl_int32(256)),  // recipient_public_key
                                   tl_ftabi_paramAddress(),            // recipient_address
                                   tl_ftabi_paramUint(tl_int32(128)),  // tokens
                                   tl_ftabi_paramUint(tl_int32(128)),  // deploy_grams
                                   tl_ftabi_paramUint(tl_int32(128)),  // transfer_grams
                               }),
                               {}));
    Expects(createdFunction.has_value());
    function = createdFunction.value();
  }
  return *function;
}

TLftabi_Function TokenInternalTransferFunction() {
  static std::optional<TLftabi_function> function;
  if (!function.has_value()) {
    const auto createdFunction = RequestSender::Execute(
        TLftabi_CreateFunction(tl_string("internalTransfer"),
                               tl_vector(QVector<TLftabi_namedParam>{
                                   tl_ftabi_namedParam(tl_string("time"), tl_ftabi_paramTime()),
                                   tl_ftabi_namedParam(tl_string("expire"), tl_ftabi_paramExpire()),
                               }),
                               tl_vector(QVector<TLftabi_Param>{
                                   tl_ftabi_paramUint(tl_int32(128)),  // tokens
                                   tl_ftabi_paramUint(tl_int32(256)),  // sender_public_key
                                   tl_ftabi_paramAddress(),            // sender_address
                                   tl_ftabi_paramAddress(),            // send_gas_to
                                   tl_ftabi_paramBool(),               // notify_receiver
                                   tl_ftabi_paramCell(),               // payload
                               }),
                               {}));
    Expects(createdFunction.has_value());
    function = createdFunction.value();
  }
  return *function;
}

TLftabi_Function TokenSwapBackFunction() {
  static std::optional<TLftabi_function> function;
  if (!function.has_value()) {
    const auto createdFunction = RequestSender::Execute(
        TLftabi_CreateFunction(tl_string("burnByOwner"),
                               tl_vector(QVector<TLftabi_namedParam>{
                                   tl_ftabi_namedParam(tl_string("time"), tl_ftabi_paramTime()),
                                   tl_ftabi_namedParam(tl_string("expire"), tl_ftabi_paramExpire()),
                               }),
                               tl_vector(QVector<TLftabi_Param>{
                                   tl_ftabi_paramUint(tl_int32(128)),  // tokens
                                   tl_ftabi_paramUint(tl_int32(128)),  // grams
                                   tl_ftabi_paramAddress(),            // callback_address
                                   tl_ftabi_paramCell(),               // callback payload
                               }),
                               {}));
    Expects(createdFunction.has_value());
    function = createdFunction.value();
  }
  return *function;
}

TLftabi_Function OrdinaryStakeFunction() {
  static std::optional<TLftabi_function> function;
  if (!function.has_value()) {
    const auto createdFunction = RequestSender::Execute(
        TLftabi_CreateFunction(tl_string("addOrdinaryStake"),
                               tl_vector(QVector<TLftabi_namedParam>{
                                   tl_ftabi_namedParam(tl_string("time"), tl_ftabi_paramTime()),
                                   tl_ftabi_namedParam(tl_string("expire"), tl_ftabi_paramExpire()),
                               }),
                               tl_vector(QVector<TLftabi_Param>{
                                   tl_ftabi_paramUint(tl_int32(64)),
                               }),
                               {}));
    Expects(createdFunction.has_value());
    function = createdFunction.value();
  }
  return *function;
}

TLftabi_Function VestingOrLockStakeFunction() {
  static std::optional<TLftabi_function> function;
  if (!function.has_value()) {
    const auto createdFunction = RequestSender::Execute(
        TLftabi_CreateFunction(tl_string("addVestingOrLock"),
                               tl_vector(QVector<TLftabi_namedParam>{
                                   tl_ftabi_namedParam(tl_string("time"), tl_ftabi_paramTime()),
                                   tl_ftabi_namedParam(tl_string("expire"), tl_ftabi_paramExpire()),
                               }),
                               tl_vector(QVector<TLftabi_Param>{
                                   tl_ftabi_paramUint(tl_int32(64)),  // stake
                                   tl_ftabi_paramAddress(),           // beneficiary
                                   tl_ftabi_paramUint(tl_int32(32)),  // withdrawalPeriod
                                   tl_ftabi_paramUint(tl_int32(32)),  // totalPeriod
                                   tl_ftabi_paramBool(),              // isVesting
                               }),
                               {}));
    Expects(createdFunction.has_value());
    function = createdFunction.value();
  }
  return *function;
}

TLftabi_Function DePoolWithdrawPartFunction() {
  static std::optional<TLftabi_function> function;
  if (!function.has_value()) {
    const auto createdFunction = RequestSender::Execute(
        TLftabi_CreateFunction(tl_string("withdrawPart"),
                               tl_vector(QVector<TLftabi_namedParam>{
                                   tl_ftabi_namedParam(tl_string("time"), tl_ftabi_paramTime()),
                                   tl_ftabi_namedParam(tl_string("expire"), tl_ftabi_paramExpire()),
                               }),
                               tl_vector(QVector<TLftabi_Param>{
                                   tl_ftabi_paramUint(tl_int32(64)),  // withdrawValue
                               }),
                               {}));
    Expects(createdFunction.has_value());
    function = createdFunction.value();
  }
  return *function;
}

TLftabi_Function DePoolWithdrawAllFunction() {
  static std::optional<TLftabi_function> function;
  if (!function.has_value()) {
    const auto createdFunction = RequestSender::Execute(
        TLftabi_CreateFunction(tl_string("withdrawAll"),
                               tl_vector(QVector<TLftabi_namedParam>{
                                   tl_ftabi_namedParam(tl_string("time"), tl_ftabi_paramTime()),
                                   tl_ftabi_namedParam(tl_string("expire"), tl_ftabi_paramExpire()),
                               }),
                               {}, {}));
    Expects(createdFunction.has_value());
    function = createdFunction.value();
  }
  return *function;
}

TLftabi_Function DePoolCancelWithdrawalFunction() {
  static std::optional<TLftabi_function> function;
  if (!function.has_value()) {
    const auto createdFunction = RequestSender::Execute(
        TLftabi_CreateFunction(tl_string("cancelWithdrawal"),
                               tl_vector(QVector<TLftabi_namedParam>{
                                   tl_ftabi_namedParam(tl_string("time"), tl_ftabi_paramTime()),
                                   tl_ftabi_namedParam(tl_string("expire"), tl_ftabi_paramExpire()),
                               }),
                               {}, {}));
    Expects(createdFunction.has_value());
    function = createdFunction.value();
  }
  return *function;
}

TLftabi_Function DePoolOnRoundCompleteFunction() {
  static std::optional<TLftabi_function> function;
  if (!function.has_value()) {
    const auto createdFunction = RequestSender::Execute(
        TLftabi_CreateFunction(tl_string("onRoundComplete"),
                               tl_vector(QVector<TLftabi_namedParam>{
                                   tl_ftabi_namedParam(tl_string("time"), tl_ftabi_paramTime()),
                                   tl_ftabi_namedParam(tl_string("expire"), tl_ftabi_paramExpire()),
                               }),
                               tl_vector(QVector<TLftabi_Param>{
                                   tl_ftabi_paramUint(tl_int32(64)),  // roundId
                                   tl_ftabi_paramUint(tl_int32(64)),  // reward
                                   tl_ftabi_paramUint(tl_int32(64)),  // ordinaryStake
                                   tl_ftabi_paramUint(tl_int32(64)),  // vestingStake
                                   tl_ftabi_paramUint(tl_int32(64)),  // lockStake
                                   tl_ftabi_paramBool(),              // reinvest
                                   tl_ftabi_paramUint(tl_int32(8)),   // reason
                               }),
                               {}));
    Expects(createdFunction.has_value());
    function = createdFunction.value();
  }
  return *function;
}

TLftabi_Function DePoolParticipantInfoFunction(int32 dePoolVersion) {
  const bool withVesting = dePoolVersion == 3;

  static std::optional<TLftabi_function> function[2];
  if (!function[withVesting].has_value()) {
    auto outputs = QVector<TLftabi_Param>{
        tl_ftabi_paramUint(tl_int32(64)),                                                       // total
        tl_ftabi_paramUint(tl_int32(64)),                                                       // withdrawValue
        tl_ftabi_paramBool(),                                                                   // reinvest
        tl_ftabi_paramUint(tl_int32(64)),                                                       // reward
        tl_ftabi_paramMap(tl_ftabi_paramUint(tl_int32(64)), tl_ftabi_paramUint(tl_int32(64))),  // stakes
        tl_ftabi_paramMap(tl_ftabi_paramUint(tl_int32(64)),
                          tl_ftabi_paramTuple(tl_vector(QVector<TLftabi_Param>{
                              tl_ftabi_paramUint(tl_int32(64)),  // remainingAmount
                              tl_ftabi_paramUint(tl_int32(64)),  // lastWithdrawalTime
                              tl_ftabi_paramUint(tl_int32(32)),  // withdrawalPeriod
                              tl_ftabi_paramUint(tl_int32(64)),  // withdrawalValue
                              tl_ftabi_paramAddress(),           // owner
                          }))),                                  // vestings
        tl_ftabi_paramMap(tl_ftabi_paramUint(tl_int32(64)),
                          tl_ftabi_paramTuple(tl_vector(QVector<TLftabi_Param>{
                              tl_ftabi_paramUint(tl_int32(64)),  // remainingAmount
                              tl_ftabi_paramUint(tl_int32(64)),  // lastWithdrawalTime
                              tl_ftabi_paramUint(tl_int32(32)),  // withdrawalPeriod
                              tl_ftabi_paramUint(tl_int32(64)),  // withdrawalValue
                              tl_ftabi_paramAddress(),           // owner
                          }))),                                  // locks
    };
    if (withVesting) {
      outputs.push_back(tl_ftabi_paramAddress());  // vestingDonor
      outputs.push_back(tl_ftabi_paramAddress());  // lockDonor
    }

    const auto createdFunction = RequestSender::Execute(
        TLftabi_CreateFunction(tl_string("getParticipantInfo"),
                               tl_vector(QVector<TLftabi_namedParam>{
                                   tl_ftabi_namedParam(tl_string("time"), tl_ftabi_paramTime()),
                                   tl_ftabi_namedParam(tl_string("expire"), tl_ftabi_paramExpire()),
                               }),
                               tl_vector(QVector<TLftabi_Param>{
                                   tl_ftabi_paramAddress(),  // addr
                               }),
                               tl_vector(outputs)));
    Expects(createdFunction.has_value());
    function[withVesting] = createdFunction.value();
  }
  return *function[withVesting];
}

std::optional<TokenTransfer> ParseTokenTransfer(const QByteArray &body) {
  const auto decodedTransferInput =
      RequestSender::Execute(TLftabi_DecodeInput(TokenTransferFunction(), tl_bytes(body), tl_boolTrue()));
  if (!decodedTransferInput.has_value()) {
    return std::nullopt;
  }

  const auto args = decodedTransferInput.value().c_ftabi_decodedInput().vvalues().v;
  if (args.size() != 3 || !IsAddress(args[0]) || !IsBigInt(args[1])) {
    return std::nullopt;
  }

  return TokenTransfer{
      .address = UnpackAddress(args[0]), .value = UnpackUint128(args[1]), .incoming = false, .direct = true};
}

std::optional<TokenTransfer> ParseTokenTransferToOwner(const QByteArray &body) {
  const auto decodedTransferInput =
      RequestSender::Execute(TLftabi_DecodeInput(TokenTransferToOwnerFunction(), tl_bytes(body), tl_boolTrue()));
  if (!decodedTransferInput.has_value()) {
    return std::nullopt;
  }

  const auto args = decodedTransferInput.value().c_ftabi_decodedInput().vvalues().v;
  if (args.size() != 5 || !IsAddress(args[1]) || !IsBigInt(args[2])) {
    return std::nullopt;
  }

  return TokenTransfer{.address = UnpackAddress(args[1]), .value = UnpackUint128(args[2]), .incoming = false};
}

std::optional<TokenTransfer> ParseInternalTokenTransfer(const QByteArray &body) {
  const auto decodedTransferInput =
      RequestSender::Execute(TLftabi_DecodeInput(TokenInternalTransferFunction(), tl_bytes(body), tl_boolTrue()));
  if (!decodedTransferInput.has_value()) {
    return std::nullopt;
  }

  const auto args = decodedTransferInput.value().c_ftabi_decodedInput().vvalues().v;
  if (args.size() != 6 || !IsBigInt(args[0]) || !IsAddress(args[2])) {
    return std::nullopt;
  }

  return TokenTransfer{.address = UnpackAddress(args[2]), .value = UnpackUint128(args[0]), .incoming = true};
}

std::optional<TokenMint> ParseTokenAccept(const QByteArray &body) {
  const auto decodedAcceptInput =
      RequestSender::Execute(TLftabi_DecodeInput(TokenAcceptFunction(), tl_bytes(body), tl_boolTrue()));
  if (!decodedAcceptInput.has_value()) {
    return std::nullopt;
  }

  const auto args = decodedAcceptInput.value().c_ftabi_decodedInput().vvalues().v;
  if (args.size() != 1 || !IsBigInt(args[0])) {
    return std::nullopt;
  }

  return TokenMint{.value = UnpackUint128(args[0])};
}

std::optional<EthEventStatus> ParseEthEventNotification(const QByteArray &body) {
  const auto decodedNotification =
      RequestSender::Execute(TLftabi_DecodeInput(EthEventStatusChangedNotification(), tl_bytes(body), tl_boolTrue()));
  if (!decodedNotification.has_value()) {
    return std::nullopt;
  }

  const auto args = decodedNotification.value().c_ftabi_decodedInput().vvalues().v;
  if (args.size() != 1 || !IsInt(args[0])) {
    return std::nullopt;
  }

  const auto status = UnpackUint(args[0]);
  switch (status) {
    case 0:
      return EthEventStatus::InProcess;
    case 1:
      return EthEventStatus::Confirmed;
    case 2:
      return EthEventStatus::Executed;
    case 3:
      return EthEventStatus::Rejected;
    default:
      return std::nullopt;
  }
}

std::optional<TonEventStatus> ParseTonEventNotification(const QByteArray &body) {
  const auto decodedNotification =
      RequestSender::Execute(TLftabi_DecodeInput(TonEventStatusChangedNotification(), tl_bytes(body), tl_boolTrue()));
  if (!decodedNotification.has_value()) {
    return std::nullopt;
  }

  const auto args = decodedNotification.value().c_ftabi_decodedInput().vvalues().v;
  if (args.size() != 1 || !IsInt(args[0])) {
    return std::nullopt;
  }

  const auto status = UnpackUint(args[0]);
  switch (status) {
    case 0:
      return TonEventStatus::InProcess;
    case 1:
      return TonEventStatus::Confirmed;
    case 2:
      return TonEventStatus::Rejected;
    default:
      return std::nullopt;
  }
}

std::optional<TokenWalletDeployed> ParseTokenWalletDeployedNotification(const QByteArray &body) {
  const auto decoded =
      RequestSender::Execute(TLftabi_DecodeInput(TokenWalletDeployedNotification(), tl_bytes(body), tl_boolTrue()));
  if (!decoded.has_value()) {
    return std::nullopt;
  }

  const auto args = decoded.value().c_ftabi_decodedInput().vvalues().v;
  if (args.size() != 1 || !IsAddress(args[0])) {
    return std::nullopt;
  }

  return TokenWalletDeployed{.rootTokenContract = UnpackAddress(args[0])};
}

std::optional<TokenSwapBack> ParseTokenSwapBack(const QByteArray &body) {
  const auto decodedSwapBackInput =
      RequestSender::Execute(TLftabi_DecodeInput(TokenSwapBackFunction(), tl_bytes(body), tl_boolTrue()));
  if (!decodedSwapBackInput.has_value()) {
    return std::nullopt;
  }

  const auto args = decodedSwapBackInput.value().c_ftabi_decodedInput().vvalues().v;
  if (args.size() != 4 || !IsBigInt(args[0]) || !IsAddress(args[2]) || !IsCell(args[3])) {
    return std::nullopt;
  }

  const auto decodedSwapBackPayload = RequestSender::Execute(TLftabi_UnpackFromCell(
      args[3].c_ftabi_valueCell().vvalue(), tl_vector(QVector<TLftabi_Param>{tl_ftabi_paramUint(tl_int32(160))})));
  if (!decodedSwapBackPayload.has_value()) {
    return std::nullopt;
  }

  const auto &payload = decodedSwapBackPayload.value().c_ftabi_decodedOutput().vvalues().v;

  auto address = payload[0].c_ftabi_valueBigInt().vvalue().v;
  address.remove(0, 32 - kEthereumAddressByteCount);
  auto addressSize = address.size();
  if (addressSize < kEthereumAddressByteCount) {
    return std::nullopt;
  } else if (addressSize > kEthereumAddressByteCount) {
    auto addressDelta = addressSize - kEthereumAddressByteCount;
    std::memmove(address.data(), address.data() + addressDelta, kEthereumAddressByteCount);
    address.resize(kEthereumAddressByteCount);
  }

  return TokenSwapBack{.address = "0x" + address.toHex(), .value = UnpackUint128(args[0])};
}

std::optional<DePoolOrdinaryStakeTransaction> ParseOrdinaryStakeTransfer(const QByteArray &body) {
  const auto decodedInput =
      RequestSender::Execute(TLftabi_DecodeInput(OrdinaryStakeFunction(), tl_bytes(body), tl_boolTrue()));
  if (!decodedInput.has_value()) {
    return std::nullopt;
  }

  const auto args = decodedInput.value().c_ftabi_decodedInput().vvalues().v;
  if (args.size() != 1 || !IsInt(args[0])) {
    return std::nullopt;
  }

  return DePoolOrdinaryStakeTransaction{.stake = UnpackUint(args[0])};
}

std::optional<DePoolOnRoundCompleteTransaction> ParseDePoolOnRoundComplete(const QByteArray &body) {
  const auto decodedInput =
      RequestSender::Execute(TLftabi_DecodeInput(DePoolOnRoundCompleteFunction(), tl_bytes(body), tl_boolTrue()));
  if (!decodedInput.has_value()) {
    return std::nullopt;
  }

  const auto args = decodedInput.value().c_ftabi_decodedInput().vvalues().v;
  if (args.size() != 7) {
    return std::nullopt;
  }

  return DePoolOnRoundCompleteTransaction{
      .roundId = UnpackUint(args[0]),
      .reward = UnpackUint(args[1]),
      .ordinaryStake = UnpackUint(args[2]),
      .vestingStake = UnpackUint(args[3]),
      .lockStake = UnpackUint(args[4]),
      .reinvest = UnpackBool(args[5]),
      .reason = static_cast<uint8>(UnpackUint(args[6])),
  };
}

std::optional<DePoolParticipantState> ParseDePoolParticipantState(int32 dePoolVersion,
                                                                  const TLftabi_decodedOutput &result) {
  const auto &results = result.c_ftabi_decodedOutput().vvalues().v;
  if (results.size() < 4) {
    return std::nullopt;
  }

  std::map<int64, int64> stakes;
  for (const auto &item : results[4].c_ftabi_valueMap().vvalues().v) {
    const auto key = UnpackUint(item.c_ftabi_valueMapItem().vkey());
    const auto value = UnpackUint(item.c_ftabi_valueMapItem().vvalue());
    stakes.emplace(std::make_pair(key, value));
  }

  return DePoolParticipantState{
      .version = dePoolVersion,
      .total = UnpackUint(results[0]),
      .withdrawValue = UnpackUint(results[1]),
      .reinvest = UnpackBool(results[2]),
      .reward = UnpackUint(results[3]),
      .stakes = std::move(stakes),
      .vestings = parseInvestParamsMap(results[5].c_ftabi_valueMap()),
      .locks = parseInvestParamsMap(results[6].c_ftabi_valueMap()),
  };
}

std::optional<RootTokenContractDetails> ParseRootTokenContractDetails(const TLftabi_decodedOutput &result) {
  const auto &tokens = result.c_ftabi_decodedOutput().vvalues().v;
  if (tokens.empty() || tokens[0].type() != id_ftabi_valueTuple) {
    return std::nullopt;
  }

  const auto &tuple = tokens[0].c_ftabi_valueTuple().vvalues().v;
  if (tuple.size() < 8 || !IsInt(tuple[2]) || !IsAddress(tuple[5]) || !IsInt(tuple[7])) {
    return std::nullopt;
  }

  return RootTokenContractDetails{
      .name = UnpackBytes(tuple[0]),
      .symbol = UnpackBytes(tuple[1]),
      .decimals = UnpackUint(tuple[2]),
      .ownerAddress = UnpackAddress(tuple[5]),
      .startGasBalance = UnpackUint(tuple[7]),
  };
}

std::optional<TokenWalletContractDetails> ParseTokenWalletContractDetails(const TLftabi_decodedOutput &result) {
  const auto &tokens = result.c_ftabi_decodedOutput().vvalues().v;
  if (tokens.empty() || tokens[0].type() != id_ftabi_valueTuple) {
    return std::nullopt;
  }

  const auto &tuple = tokens[0].c_ftabi_valueTuple().vvalues().v;
  if (tuple.size() < 5 || !IsAddress(tuple[0]) || !IsAddress(tuple[3])) {
    return std::nullopt;
  }

  return TokenWalletContractDetails{
      .rootAddress = UnpackAddress(tuple[0]),
      .ownerAddress = UnpackAddress(tuple[3]),
  };
}

Result<QByteArray> CreateTokenMessage(const QString &recipient, const int128 &amount) {
  const auto encodedBody = RequestSender::Execute(TLftabi_CreateMessageBody(
      TokenTransferFunction(), tl_ftabi_functionCallInternal({}, tl_vector(QVector<TLftabi_Value>{
                                                                     PackAddress(recipient),  // to
                                                                     PackUint128(amount),     // amount
                                                                     PackUint128(),           // grams
                                                                 }))));
  if (!encodedBody.has_value()) {
    return encodedBody.error();
  }

  return encodedBody.value().c_ftabi_messageBody().vdata().v;
}

Result<QByteArray> CreateTokenTransferToOwnerMessage(const QString &recipient, const int128 &amount,
                                                     int64 deployGrams) {
  const auto encodedBody = RequestSender::Execute(TLftabi_CreateMessageBody(  //
      TokenTransferToOwnerFunction(),
      tl_ftabi_functionCallInternal({}, tl_vector(QVector<TLftabi_Value>{
                                            PackPubKey(),              // recipient_public_key
                                            PackAddress(recipient),    // recipient_address
                                            PackUint128(amount),       // tokens
                                            PackUint128(deployGrams),  // deploy_grams
                                            PackUint128(),             // transfer_grams
                                        }))));
  if (!encodedBody.has_value()) {
    return encodedBody.error();
  }

  return encodedBody.value().c_ftabi_messageBody().vdata().v;
}

std::optional<QByteArray> ParseEthereumAddress(const QString &ethereumAddress) {
  if (!ethereumAddress.startsWith("0x")) {
    return std::nullopt;
  }
  const auto target = ethereumAddress.mid(2, -1);
  const auto targetBytes = QByteArray::fromHex(target.toUtf8());
  if (targetBytes.size() != kEthereumAddressByteCount) {
    return std::nullopt;
  }
  return targetBytes;
}

Result<QByteArray> CreateSwapBackMessage(QByteArray ethereumAddress, const QString &callback_address,
                                         const int128 &amount) {
  Expects(ethereumAddress.size() == kEthereumAddressByteCount);
  ethereumAddress.prepend(32 - kEthereumAddressByteCount, 0);

  auto callback_payload = RequestSender::Execute(TLftabi_PackIntoCell(tl_vector(
      QVector<TLftabi_Value>{tl_ftabi_valueBigInt(tl_ftabi_paramUint(tl_int32(160)), tl_bytes(ethereumAddress))})));
  if (!callback_payload.has_value()) {
    return callback_payload.error();
  }

  const auto encodedBody = RequestSender::Execute(TLftabi_CreateMessageBody(
      TokenSwapBackFunction(),  //
      tl_ftabi_functionCallInternal({}, tl_vector(QVector<TLftabi_Value>{
                                            PackUint128(amount),                 // tokens
                                            PackUint128(),                       // grams
                                            PackAddress(callback_address),       // callback_address
                                            PackCell(callback_payload.value()),  // callback_payload
                                        }))));
  if (!encodedBody.has_value()) {
    return encodedBody.error();
  }

  return encodedBody.value().c_ftabi_messageBody().vdata().v;
}

Result<QByteArray> CreateStakeMessage(int64 stake) {
  const auto encodedBody = RequestSender::Execute(TLftabi_CreateMessageBody(
      OrdinaryStakeFunction(), tl_ftabi_functionCallInternal({}, tl_vector(QVector<TLftabi_Value>{
                                                                     tl_ftabi_valueInt(tl_ftabi_paramUint(tl_int32(64)),
                                                                                       tl_int64(stake)),  // stake
                                                                 }))));
  if (!encodedBody.has_value()) {
    return encodedBody.error();
  }

  return encodedBody.value().c_ftabi_messageBody().vdata().v;
}

Result<QByteArray> CreateWithdrawalMessage(int64 amount, bool all) {
  TLftabi_Function function{};
  TLftabi_FunctionCall functionCall{};
  if (all) {
    function = DePoolWithdrawAllFunction();
    functionCall = tl_ftabi_functionCallInternal({}, {});
  } else {
    function = DePoolWithdrawPartFunction();
    functionCall = tl_ftabi_functionCallInternal({}, tl_vector(QVector<TLftabi_Value>{
                                                         tl_ftabi_valueInt(tl_ftabi_paramUint(tl_int32(64)),
                                                                           tl_int64(amount)),  // withdrawValue
                                                     }));
  }
  const auto encodedBody =
      RequestSender::Execute(TLftabi_CreateMessageBody(std::move(function), std::move(functionCall)));
  if (!encodedBody.has_value()) {
    return encodedBody.error();
  }

  return encodedBody.value().c_ftabi_messageBody().vdata().v;
}

Result<QByteArray> CreateCancelWithdrawalMessage() {
  const auto encodedBody = RequestSender::Execute(
      TLftabi_CreateMessageBody(DePoolCancelWithdrawalFunction(), tl_ftabi_functionCallInternal({}, {})));
  if (!encodedBody.has_value()) {
    return encodedBody.error();
  }

  return encodedBody.value().c_ftabi_messageBody().vdata().v;
}

Result<QByteArray> CreateTokenWalletDeployMessage(int64 grams, const QString &owner) {
  const auto encodedBody = RequestSender::Execute(
      TLftabi_CreateMessageBody(RootTokenDeployWalletFunction(),  //
                                tl_ftabi_functionCallInternal({}, tl_vector(QVector<TLftabi_Value>{
                                                                      PackUint128(grams),
                                                                      PackPubKey(),
                                                                      PackAddress(owner),
                                                                      PackAddress(owner),
                                                                  }))));
  if (!encodedBody.has_value()) {
    return encodedBody.error();
  }

  return encodedBody.value().c_ftabi_messageBody().vdata().v;
}

Result<QByteArray> CreateExecuteProxyCallbackMessage() {
  static auto encodedBody = RequestSender::Execute(
      TLftabi_CreateMessageBody(ExecuteProxyCallbackFunction(), tl_ftabi_functionCallInternal({}, {})));
  if (!encodedBody.has_value()) {
    return encodedBody.error();
  }

  return encodedBody.value().c_ftabi_messageBody().vdata().v;
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

  _gateUrl = "https://gate.broxus.com/";
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

std::optional<Ton::TokenTransaction> Wallet::ParseTokenTransaction(const Ton::MessageData &message) {
  if (message.type != Ton::MessageDataType::RawBody) {
    return std::nullopt;
  }

  if (auto transfer = ParseTokenTransfer(message.data); transfer.has_value()) {
    return *transfer;
  } else if (auto internalTransfer = ParseInternalTokenTransfer(message.data); internalTransfer.has_value()) {
    return *internalTransfer;
  } else if (auto transferToOwner = ParseTokenTransferToOwner(message.data); transferToOwner.has_value()) {
    return *transferToOwner;
  } else if (auto mint = ParseTokenAccept(message.data); mint.has_value()) {
    return *mint;
  } else if (auto swapBack = ParseTokenSwapBack(message.data); swapBack.has_value()) {
    return *swapBack;
  } else {
    return std::nullopt;
  }
}

std::optional<Ton::DePoolTransaction> Wallet::ParseDePoolTransaction(const Ton::MessageData &message, bool incoming) {
  if (message.type != Ton::MessageDataType::RawBody) {
    return std::nullopt;
  }

  if (incoming) {
    if (auto onRoundComplete = ParseDePoolOnRoundComplete(message.data); onRoundComplete.has_value()) {
      return *onRoundComplete;
    }
  } else {
    if (auto ordinaryState = ParseOrdinaryStakeTransfer(message.data); ordinaryState.has_value()) {
      return *ordinaryState;
    }
  }

  return std::nullopt;
}

std::optional<Ton::Notification> Wallet::ParseNotification(const Ton::MessageData &message) {
  if (message.type != Ton::MessageDataType::RawBody) {
    return std::nullopt;
  }

  if (auto ethEventNotification = ParseEthEventNotification(message.data); ethEventNotification.has_value()) {
    return EthEventStatusChanged{.status = *ethEventNotification};
  } else if (auto tonEventNotification = ParseTonEventNotification(message.data); tonEventNotification.has_value()) {
    return TonEventStatusChanged{.status = *tonEventNotification};
  } else if (auto walletDeployed = ParseTokenWalletDeployedNotification(message.data); walletDeployed.has_value()) {
    return *walletDeployed;
  } else {
    return std::nullopt;
  }
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
      updateSettings(copy, std::move(done));
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

void Wallet::createKey(const Callback<std::vector<QString>> &done) {
  Expects(_keyCreator == nullptr);
  Expects(_keyDestroyer == nullptr);
  Expects(_passwordChanger == nullptr);

  auto created = [=](const Result<std::vector<QString>> &result) {
    const auto destroyed = result ? std::unique_ptr<KeyCreator>() : base::take(_keyCreator);
    InvokeCallback(done, result);
  };
  _keyCreator = std::make_unique<KeyCreator>(&_external->lib(), &_external->db(), std::move(created));
}

void Wallet::importKey(const std::vector<QString> &words, const Callback<> &done) {
  Expects(_keyCreator == nullptr);
  Expects(_keyDestroyer == nullptr);
  Expects(_passwordChanger == nullptr);

  auto created = [=](Result<> result) {
    const auto destroyed = result ? std::unique_ptr<KeyCreator>() : base::take(_keyCreator);
    InvokeCallback(done, result);
  };
  _keyCreator = std::make_unique<KeyCreator>(&_external->lib(), &_external->db(), words, std::move(created));
}

void Wallet::queryWalletAddress(const Callback<QString> &done) {
  Expects(_keyCreator != nullptr);
  Expects(_configInfo.has_value());

  _keyCreator->queryWalletAddress(_configInfo->restrictedInitPublicKey, std::move(done));
}

void Wallet::saveKey(const QByteArray &password, const QString &address, const Callback<QByteArray> &done) {
  Expects(_keyCreator != nullptr);

  auto saved = [=](Result<WalletList::Entry> result) {
    if (!result) {
      return InvokeCallback(done, result.error());
    }
    const auto destroyed = base::take(_keyCreator);
    _list->entries.push_back(*result);
    InvokeCallback(done, result->publicKey);
  };
  _keyCreator->save(password, *_list,
                    (address.isEmpty() ? getDefaultAddress(_keyCreator->key(), kDefaultWorkchainId) : address),
                    settings().useTestNetwork, std::move(saved));
}

void Wallet::exportKey(const QByteArray &publicKey, const QByteArray &password,
                       const Callback<std::vector<QString>> &done) {
  _external->lib()
      .request(TLExportKey(prepareInputKey(publicKey, password)))
      .done([=](const TLExportedKey &result) { InvokeCallback(done, Parse(result)); })
      .fail([=](const TLError &error) { InvokeCallback(done, ErrorFromLib(error)); })
      .send();
}

TLinputKey Wallet::prepareInputKey(const QByteArray &publicKey, const QByteArray &password) const {
  const auto i = ranges::find(_list->entries, publicKey, &WalletList::Entry::publicKey);
  Assert(i != end(_list->entries));

  return tl_inputKeyRegular(tl_key(tl_string(publicKey), TLsecureBytes{i->secret}), TLsecureBytes{password});
}

void Wallet::setWalletList(const WalletList &list) {
  Expects(_list->entries.empty());

  *_list = list;
}

void Wallet::deleteKey(const QByteArray &publicKey, const Callback<> &done) {
  Expects(_keyCreator == nullptr);
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
  _keyDestroyer = std::make_unique<KeyDestroyer>(&_external->lib(), &_external->db(), std::move(list), index,
                                                 settings().useTestNetwork, std::move(removed));
}

void Wallet::deleteAllKeys(const Callback<> &done) {
  Expects(_keyCreator == nullptr);
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
  Expects(_keyCreator == nullptr);
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

void Wallet::checkSendGrams(const QByteArray &publicKey, const TransactionToSend &transaction,
                            const Callback<TransactionCheckResult> &done) {
  Expects(transaction.amount >= 0);

  const auto sender = getUsedAddress(publicKey);
  Assert(!sender.isEmpty());

  checkTransactionFees(
      sender, transaction.recipient,
      (transaction.sendUnencryptedText ? tl_msg_dataText : tl_msg_dataDecryptedText)(tl_string(transaction.comment)),
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
      return done(std::make_pair(TransactionCheckResult{}, InvalidEthAddress{}));
    }
    auto body = CreateSwapBackMessage(ethereumAddress.value(), transaction.callbackAddress, transaction.amount);
    if (!body.has_value()) {
      return InvokeCallback(done, body.error());
    }
    return checkTransactionFees(  //
        sender, transaction.walletContractAddress, tl_msg_dataRaw(tl_bytes(body.value()), tl_bytes()),
        TokenTransactionToSend::realAmount, transaction.timeout, false, [=](Result<TransactionCheckResult> &&result) {
          if (result.has_value()) {
            done(std::make_pair(std::move(result.value()), TokenTransferUnchanged{}));
          } else {
            done(result.error());
          }
        });
  }

  const auto checkWalletAddress = [=](const QString &recipientTokenWallet) {
    _external->lib()
        .request(TLGetAccountState(tl_accountAddress(tl_string(recipientTokenWallet))))
        .done([=](const TLFullAccountState &result) {
          const auto isUninit = result.c_fullAccountState().vaccount_state().type() == id_uninited_accountState;

          if (isUninit && transaction.tokenTransferType == TokenTransferType::Direct) {
            done(std::make_pair(TransactionCheckResult{}, DirectAccountNotFound{}));
          } else if (isUninit) {
            auto body = CreateTokenTransferToOwnerMessage(transaction.recipient, transaction.amount,
                                                          TokenTransactionToSend::initialBalance);
            if (!body.has_value()) {
              return InvokeCallback(done, body.error());
            }
            checkTransactionFees(  //
                sender, transaction.walletContractAddress, tl_msg_dataRaw(tl_bytes(body.value()), tl_bytes()),
                TokenTransactionToSend::realAmount, transaction.timeout, false,
                [=](Result<TransactionCheckResult> result) {
                  if (result.has_value()) {
                    done(std::make_pair(std::move(result.value()), TokenTransferUnchanged{}));
                  } else {
                    done(result.error());
                  }
                });
          } else {
            auto body = CreateTokenMessage(recipientTokenWallet, transaction.amount);
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
                    done(std::make_pair(std::move(result.value()), std::move(transferCheckResult)));
                  } else {
                    done(result.error());
                  }
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
               ownerAddress = transaction.recipient](const TLftabi_decodedOutput &decodedOutput) {
          const auto &tokens = decodedOutput.c_ftabi_decodedOutput().vvalues().v;
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

  const auto body = CreateStakeMessage(transaction.stake);
  if (!body.has_value()) {
    return InvokeCallback(done, body.error());
  }

  const auto realAmount = StakeTransactionToSend::depoolFee + transaction.stake;
  checkTransactionFees(sender, transaction.depoolAddress, tl_msg_dataRaw(tl_bytes(body.value()), tl_bytes()),
                       realAmount, transaction.timeout, false, done);
}

void Wallet::checkWithdraw(const QByteArray &publicKey, const WithdrawalTransactionToSend &transaction,
                           const Callback<TransactionCheckResult> &done) {
  Expects(transaction.all || transaction.amount >= 0);

  const auto sender = getUsedAddress(publicKey);
  Assert(!sender.isEmpty());

  const auto body = CreateWithdrawalMessage(transaction.amount, transaction.all);
  if (!body.has_value()) {
    return InvokeCallback(done, body.error());
  }

  checkTransactionFees(sender, transaction.depoolAddress, tl_msg_dataRaw(tl_bytes(body.value()), tl_bytes()),
                       WithdrawalTransactionToSend::depoolFee, transaction.timeout, false, done);
}

void Wallet::checkCancelWithdraw(const QByteArray &publicKey, const CancelWithdrawalTransactionToSend &transaction,
                                 const Callback<TransactionCheckResult> &done) {
  const auto sender = getUsedAddress(publicKey);
  Assert(!sender.isEmpty());

  const auto body = CreateCancelWithdrawalMessage();
  if (!body.has_value()) {
    return InvokeCallback(done, body.error());
  }

  checkTransactionFees(sender, transaction.depoolAddress, tl_msg_dataRaw(tl_bytes(body.value()), tl_bytes()),
                       CancelWithdrawalTransactionToSend::depoolFee, transaction.timeout, false, done);
}

void Wallet::checkDeployTokenWallet(const QByteArray &publicKey, const DeployTokenWalletTransactionToSend &transaction,
                                    const Callback<TransactionCheckResult> &done) {
  const auto sender = getUsedAddress(publicKey);
  Assert(!sender.isEmpty());

  const auto body = CreateTokenWalletDeployMessage(DeployTokenWalletTransactionToSend::initialBalance, sender);
  if (!body.has_value()) {
    return InvokeCallback(done, body.error());
  }

  checkTransactionFees(sender, transaction.rootContractAddress, tl_msg_dataRaw(tl_bytes(body.value()), tl_bytes()),
                       DeployTokenWalletTransactionToSend::realAmount, transaction.timeout, false, done);
}

void Wallet::checkCollectTokens(const QByteArray &publicKey, const CollectTokensTransactionToSend &transaction,
                                const Callback<TransactionCheckResult> &done) {
  const auto sender = getUsedAddress(publicKey);
  Assert(!sender.isEmpty());

  const auto body = CreateExecuteProxyCallbackMessage();
  if (!body.has_value()) {
    return InvokeCallback(done, body.error());
  }

  checkTransactionFees(sender, transaction.eventContractAddress, tl_msg_dataRaw(tl_bytes(body.value()), tl_bytes()),
                       CollectTokensTransactionToSend::realAmount, transaction.timeout, true, done);
}

void Wallet::sendGrams(const QByteArray &publicKey, const QByteArray &password, const TransactionToSend &transaction,
                       const Callback<PendingTransaction> &ready, const Callback<> &done) {
  Expects(transaction.amount >= 0);

  const auto sender = getUsedAddress(publicKey);
  Assert(!sender.isEmpty());

  sendMessage(
      publicKey, password, sender, transaction.recipient,
      (transaction.sendUnencryptedText ? tl_msg_dataText : tl_msg_dataDecryptedText)(tl_string(transaction.comment)),
      transaction.amount, transaction.timeout, transaction.allowSendToUninited, transaction.comment,
      transaction.sendUnencryptedText, ready, done);
}

void Wallet::sendTokens(const QByteArray &publicKey, const QByteArray &password,
                        const TokenTransactionToSend &transaction, const Callback<PendingTransaction> &ready,
                        const Callback<> &done) {
  Expects(transaction.amount >= 0);

  const auto sender = getUsedAddress(publicKey);
  Assert(!sender.isEmpty());

  Result<QByteArray> body{};
  switch (transaction.tokenTransferType) {
    case TokenTransferType::Direct: {
      body = CreateTokenMessage(transaction.recipient, transaction.amount);
      break;
    }
    case TokenTransferType::ToOwner: {
      body = CreateTokenTransferToOwnerMessage(transaction.recipient, transaction.amount,
                                               TokenTransactionToSend::initialBalance);
      break;
    }
    case TokenTransferType::SwapBack: {
      const auto ethereumAddress = ParseEthereumAddress(transaction.recipient);
      if (!ethereumAddress.has_value()) {
        return InvokeCallback(done, Error{Error::Type::Web, "Invalid ethereum address"});
      }
      body = CreateSwapBackMessage(ethereumAddress.value(), transaction.callbackAddress, transaction.amount);
      break;
    }
  }
  if (!body.has_value()) {
    return InvokeCallback(done, body.error());
  }

  const auto realAmount = TokenTransactionToSend::realAmount;

  sendMessage(publicKey, password, sender, transaction.walletContractAddress,
              tl_msg_dataRaw(tl_bytes(body.value()), tl_bytes()), realAmount, transaction.timeout, false, ready, done);
}

void Wallet::withdraw(const QByteArray &publicKey, const QByteArray &password,
                      const WithdrawalTransactionToSend &transaction, const Callback<PendingTransaction> &ready,
                      const Callback<> &done) {
  Expects(transaction.all || transaction.amount >= 0);

  const auto sender = getUsedAddress(publicKey);
  Assert(!sender.isEmpty());

  const auto body = CreateWithdrawalMessage(transaction.amount, transaction.all);
  if (!body.has_value()) {
    return InvokeCallback(done, body.error());
  }

  const auto realAmount = WithdrawalTransactionToSend::depoolFee;

  sendMessage(publicKey, password, sender, transaction.depoolAddress,
              tl_msg_dataRaw(tl_bytes(body.value()), tl_bytes()), realAmount, transaction.timeout, false, ready, done);
}

void Wallet::cancelWithdrawal(const QByteArray &publicKey, const QByteArray &password,
                              const CancelWithdrawalTransactionToSend &transaction,
                              const Callback<PendingTransaction> &ready, const Callback<> &done) {
  const auto sender = getUsedAddress(publicKey);
  Assert(!sender.isEmpty());

  const auto body = CreateCancelWithdrawalMessage();
  if (!body.has_value()) {
    return InvokeCallback(done, body.error());
  }

  const auto realAmount = CancelWithdrawalTransactionToSend::depoolFee;

  sendMessage(publicKey, password, sender, transaction.depoolAddress,
              tl_msg_dataRaw(tl_bytes(body.value()), tl_bytes()), realAmount, transaction.timeout, false, ready, done);
}

void Wallet::deployTokenWallet(const QByteArray &publicKey, const QByteArray &password,
                               const DeployTokenWalletTransactionToSend &transaction,
                               const Callback<PendingTransaction> &ready, const Callback<> &done) {
  const auto sender = getUsedAddress(publicKey);
  Assert(!sender.isEmpty());

  const auto body = CreateTokenWalletDeployMessage(DeployTokenWalletTransactionToSend::initialBalance, sender);
  if (!body.has_value()) {
    return InvokeCallback(done, body.error());
  }

  const auto realAmount = DeployTokenWalletTransactionToSend::realAmount;

  sendMessage(publicKey, password, sender, transaction.rootContractAddress,
              tl_msg_dataRaw(tl_bytes(body.value()), tl_bytes()), realAmount, transaction.timeout, false, ready, done);
}

void Wallet::collectTokens(const QByteArray &publicKey, const QByteArray &password,
                           const CollectTokensTransactionToSend &transaction, const Callback<PendingTransaction> &ready,
                           const Callback<> &done) {
  const auto sender = getUsedAddress(publicKey);
  Assert(!sender.isEmpty());

  const auto body = CreateExecuteProxyCallbackMessage();
  if (!body.has_value()) {
    return InvokeCallback(done, body.error());
  }

  const auto realAmount = CollectTokensTransactionToSend::realAmount;

  sendMessage(publicKey, password, sender, transaction.eventContractAddress,
              tl_msg_dataRaw(tl_bytes(body.value()), tl_bytes()), realAmount, transaction.timeout, true, ready, done);
}

void Wallet::sendStake(const QByteArray &publicKey, const QByteArray &password,
                       const StakeTransactionToSend &transaction, const Callback<PendingTransaction> &ready,
                       const Callback<> &done) {
  Expects(transaction.stake >= 0);

  const auto sender = getUsedAddress(publicKey);
  Assert(!sender.isEmpty());

  const auto body = CreateStakeMessage(transaction.stake);
  if (!body.has_value()) {
    return InvokeCallback(done, body.error());
  }

  const auto realAmount = StakeTransactionToSend::depoolFee + transaction.stake;

  sendMessage(publicKey, password, sender, transaction.depoolAddress,
              tl_msg_dataRaw(tl_bytes(body.value()), tl_bytes()), realAmount, transaction.timeout, false, ready, done);
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

void Wallet::openReveal(const QString &rawAddress, const QString &ethereumAddress) {
  auto url = QUrl(_gateUrl);
  url.setQuery(QString{"TONAddress=%1&revealEthereumAddress=%2"}.arg(rawAddress, ethereumAddress));
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
            .done([=](const TLftabi_decodedOutput &decodedOutput) {
              auto state = ParseDePoolParticipantState(*dePoolVersion, decodedOutput);
              if (state.has_value()) {
                _accountViewers->addDePool(account, packedDePoolAddress, std::move(state.value()));
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
        .done([=](const TLftabi_decodedOutput &decodedOutput) {
          const auto &tokens = decodedOutput.c_ftabi_decodedOutput().vvalues().v;
          const auto walletAddress = UnpackAddress(tokens[0]);

          _accountViewers->addToken(
              account, TokenState{.token = Symbol::tip3(details.symbol, details.decimals, packedRootContractAddress),
                                  .walletContractAddress = walletAddress,
                                  .rootOwnerAddress = details.ownerAddress,
                                  .balance = 0});
          InvokeCallback(done);
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
            .done([=, result = std::move(result)](const TLftabi_decodedOutput &decodedDetailsOutput) mutable {
              auto details = ParseRootTokenContractDetails(decodedDetailsOutput);
              if (details.has_value()) {
                getWalletAddress(std::move(result), details.value());
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

          auto getBalance = [=, result = std::move(result)](TransactionsSlice &&lastTransactions) {
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
                .done([=, result = std::move(result)](const TLftabi_decodedOutput &balanceOutput) mutable {
                  const auto &results = balanceOutput.c_ftabi_decodedOutput().vvalues().v;
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
              .done(
                  [getBalance = std::move(getBalance)](const TLraw_Transactions &result) { getBalance(Parse(result)); })
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
        .done([=, address = address, previousState = previousState](const TLftabi_decodedOutput &result) {
          auto state = ParseDePoolParticipantState(previousState.version, result);
          if (state.has_value()) {
            ctx->notifySuccess(address, std::move(state.value()));
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
      .done([=](const TLftabi_decodedOutput &decodedOutput) {
        const auto details = ParseTokenWalletContractDetails(decodedOutput);
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
        .done([=](const TLftabi_decodedOutput &decodedOutput) {
          auto details = ParseTokenWalletContractDetails(decodedOutput);

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
  sendMessage(publicKey, password, sender, recipient, body, realAmount, timeout, allowSendToUninited, QString{}, false,
              ready, done);
}

void Wallet::sendMessage(const QByteArray &publicKey, const QByteArray &password, const QString &sender,
                         const QString &recipient, const tl::boxed<Ton::details::TLmsg_data> &body, int64 realAmount,
                         int timeout, bool allowSendToUninited, const QString &comment, bool sendUnencryptedText,
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

}  // namespace Ton
