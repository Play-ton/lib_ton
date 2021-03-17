#include "ton_abi.h"

#include "ton/details/ton_request_sender.h"
#include "ton/ton_state.h"

#include "contracts/safe_multisig_wallet_tvc.h"
#include "contracts/safe_multisig_wallet_24h_tvc.h"
#include "contracts/setcode_multisig_wallet_tvc.h"
#include "contracts/surf_tvc.h"

namespace Ton::details {

constexpr auto kEthereumAddressByteCount = 20;

template <typename T, size_t N>
auto LoadSlice(T (&data)[N]) -> QByteArray {
  return QByteArray(reinterpret_cast<const char *>(data), N * sizeof(T));
}

void CreateInternalMessageBody(RequestSender &lib, const TLftabi_Function &function, QVector<TLftabi_Value> &&inputs,
                               const MessageBodyCallback &done) {
  lib.request(TLftabi_CreateMessageBody(function, tl_ftabi_functionCallInternal(
                                                      tl_vector(std::forward<std::decay_t<decltype(inputs)>>(inputs)))))
      .done([done](TLftabi_MessageBody &&response) { InvokeCallback(done, response.c_ftabi_messageBody().vdata().v); })
      .fail([done](TLError &&error) { InvokeCallback(done, ErrorFromLib(error)); })
      .send();
}

void CreateExternalSignedMessageBody(RequestSender &lib, const TLftabi_Function &function,
                                     QVector<TLftabi_Value> &&inputs, const TLInputKey &inputKey,
                                     const MessageBodyCallback &done) {
  lib.request(TLftabi_CreateMessageBody(
                  function, tl_ftabi_functionCallExternalSigned(
                                {}, tl_vector(std::forward<std::decay_t<decltype(inputs)>>(inputs)), inputKey)))
      .done([done](TLftabi_MessageBody &&response) { InvokeCallback(done, response.c_ftabi_messageBody().vdata().v); })
      .fail([done](TLError &&error) { InvokeCallback(done, ErrorFromLib(error)); })
      .send();
}

[[nodiscard]] QByteArray UnpackPubkey(const TLftabi_Value &value) {
  return value.match(
      [](const TLDftabi_valueInt &value) {
        auto number = value.vvalue().v;
        QByteArray result(32, 0);
        for (auto i = 0; i < sizeof(number) || number != 0; --i) {
          result[i] = static_cast<char>(number & 0xff);
          number >>= 8;
        }
        return result;
      },
      [](const TLDftabi_valueBigInt &value) { return value.vvalue().v; },
      [](auto &&) {
        Unexpected("ftabi value");
        return QByteArray{};
      });
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

[[nodiscard]] TLftabi_Value PackUint64(int64 value) {
  return tl_ftabi_valueInt(tl_ftabi_paramUint(tl_int32(64)), tl_int64(value));
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

[[nodiscard]] TLftabi_Value PackBool(bool value) {
  return tl_ftabi_valueBool(tl_ftabi_paramBool(), value ? tl_boolTrue() : tl_boolFalse());
}

[[nodiscard]] bool UnpackBool(const TLftabi_Value &value) {
  return value.c_ftabi_valueBool().vvalue().type() == id_boolTrue;
}

[[nodiscard]] QByteArray UnpackBytes(const TLftabi_Value &value) {
  return value.c_ftabi_valueBytes().vvalue().v;
}

[[nodiscard]] TLftabi_Value PackBytes(const QByteArray &value) {
  return tl_ftabi_valueBytes(tl_ftabi_paramBytes(), tl_bytes(value));
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

bool IsBytes(const TLftabi_Value &value) {
  return value.type() == id_ftabi_valueBytes;
}

bool IsCell(const TLftabi_Value &value) {
  return value.type() == id_ftabi_valueCell;
}

[[nodiscard]] TLVector<TLftabi_namedParam> DefaultHeaders() {
  return tl_vector(QVector<TLftabi_namedParam>{
      tl_ftabi_namedParam(tl_string("time"), tl_ftabi_paramTime()),
      tl_ftabi_namedParam(tl_string("expire"), tl_ftabi_paramExpire()),
  });
}

[[nodiscard]] TLVector<TLftabi_namedParam> ExtendedHeaders() {
  return tl_vector(QVector<TLftabi_namedParam>{
      tl_ftabi_namedParam(tl_string("pubkey"), tl_ftabi_paramPublicKey()),
      tl_ftabi_namedParam(tl_string("time"), tl_ftabi_paramTime()),
      tl_ftabi_namedParam(tl_string("expire"), tl_ftabi_paramExpire()),
  });
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

TLftabi_Function TransferWithComment() {
  static TLftabi_Function function = tl_ftabi_function(  //
      tl_string("transfer"), {},
      tl_vector(QVector<TLftabi_Param>{
          tl_ftabi_paramBytes(),  // comment
      }),
      {},                      // output
      tl_int32(0x00000000u),   // input id
      tl_int32(0x80000000u));  // output id
  return function;
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
    const auto createdFunction = RequestSender::Execute(TLftabi_CreateFunction(  //
        tl_string("notifyTonEventStatusChanged"), {},
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
    const auto createdFunction = RequestSender::Execute(TLftabi_CreateFunction(  //
        tl_string("notifyWalletDeployed"), {}, tl_vector(QVector<TLftabi_Param>{tl_ftabi_paramAddress()}), {}));
    Expects(createdFunction.has_value());
    function = createdFunction.value();
  }
  return *function;
}

TLftabi_Function EthEventGetDetailsFunction() {
  static std::optional<TLftabi_function> function;
  if (!function.has_value()) {
    const auto createdFunction = RequestSender::Execute(TLftabi_CreateFunction(  //
        tl_string("getDetails"), DefaultHeaders(), {},
        tl_vector(QVector<TLftabi_Param>{
            tl_ftabi_paramTuple(tl_vector(QVector<TLftabi_Param>{
                tl_ftabi_paramUint(tl_int32(256)),         // eventTransaction
                tl_ftabi_paramUint(tl_int32(32)),          // eventIndex
                tl_ftabi_paramCell(),                      // eventData
                tl_ftabi_paramUint(tl_int32(32)),          // eventBlockNumber
                tl_ftabi_paramUint(tl_int32(256)),         // eventBlock
                tl_ftabi_paramAddress(),                   // ethereumEventConfiguration
                tl_ftabi_paramUint(tl_int32(16)),          // requiredConfirmations
                tl_ftabi_paramUint(tl_int32(16)),          // requiredRejects
                tl_ftabi_paramAddress(),                   // proxyAddress
                tl_ftabi_paramCell(),                      // configurationMeta
            })),                                           // initData
            tl_ftabi_paramUint(tl_int32(8)),               // status
            tl_ftabi_paramArray(tl_ftabi_paramAddress()),  // confirmRelays
            tl_ftabi_paramArray(tl_ftabi_paramAddress()),  // rejectRelays
        })));
    Expects(createdFunction.has_value());
    function = createdFunction.value();
  }
  return *function;
}

TLftabi_Function EthEventGetDecodedDataFunction() {
  static std::optional<TLftabi_function> function;
  if (!function.has_value()) {
    const auto createdFunction = RequestSender::Execute(TLftabi_CreateFunction(  //
        tl_string("getDecodedData"), DefaultHeaders(), {},
        tl_vector(QVector<TLftabi_Param>{
            tl_ftabi_paramAddress(),            // rootToken
            tl_ftabi_paramUint(tl_int32(128)),  // tokens
            tl_ftabi_paramInt(tl_int32(8)),     // wid
            tl_ftabi_paramUint(tl_int32(256)),  // owner_addr
            tl_ftabi_paramUint(tl_int32(256)),  // owner_pubkey
            tl_ftabi_paramAddress(),            // owner_address
        })));
    Expects(createdFunction.has_value());
    function = createdFunction.value();
  }
  return *function;
}

TLftabi_Function TonEventGetDetailsFunction() {
  static std::optional<TLftabi_function> function;
  if (!function.has_value()) {
    const auto createdFunction = RequestSender::Execute(TLftabi_CreateFunction(  //
        tl_string("getDetails"), DefaultHeaders(), {},
        tl_vector(QVector<TLftabi_Param>{
            tl_ftabi_paramTuple(tl_vector(QVector<TLftabi_Param>{
                tl_ftabi_paramUint(tl_int32(256)),         // eventTransaction
                tl_ftabi_paramUint(tl_int32(64)),          // eventTransactionLt
                tl_ftabi_paramUint(tl_int32(32)),          // eventTimestamp
                tl_ftabi_paramUint(tl_int32(32)),          // eventIndex
                tl_ftabi_paramCell(),                      // eventData
                tl_ftabi_paramAddress(),                   // tonEventConfiguration
                tl_ftabi_paramUint(tl_int32(16)),          // requiredConfirmations
                tl_ftabi_paramUint(tl_int32(16)),          // requiredRejects
                tl_ftabi_paramCell(),                      // configurationMeta
            })),                                           // initData
            tl_ftabi_paramUint(tl_int32(8)),               // status
            tl_ftabi_paramArray(tl_ftabi_paramAddress()),  // confirmRelays
            tl_ftabi_paramArray(tl_ftabi_paramAddress()),  // rejectRelays
            tl_ftabi_paramArray(tl_ftabi_paramBytes()),    // eventDataSignatures
        })));
    Expects(createdFunction.has_value());
    function = createdFunction.value();
  }
  return *function;
}

TLftabi_Function TonEventGetDecodedDataFunction() {
  static std::optional<TLftabi_function> function;
  if (!function.has_value()) {
    const auto createdFunction = RequestSender::Execute(TLftabi_CreateFunction(  //
        tl_string("getDecodedData"), DefaultHeaders(), {},
        tl_vector(QVector<TLftabi_Param>{
            tl_ftabi_paramAddress(),            // rootToken
            tl_ftabi_paramInt(tl_int32(8)),     // wid
            tl_ftabi_paramUint(tl_int32(256)),  // addr
            tl_ftabi_paramUint(tl_int32(128)),  // tokens
            tl_ftabi_paramUint(tl_int32(160)),  // ethereum_address
            tl_ftabi_paramAddress(),            // owner_address
        })));
    Expects(createdFunction.has_value());
    function = createdFunction.value();
  }
  return *function;
}

TLftabi_Function TokenWalletGetDetailsFunction() {
  static std::optional<TLftabi_function> function;
  if (!function.has_value()) {
    const auto createdFunction = RequestSender::Execute(TLftabi_CreateFunction(  //
        tl_string("getDetails"), ExtendedHeaders(), {},
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
    const auto createdFunction = RequestSender::Execute(TLftabi_CreateFunction(  //
        tl_string("getDetails"), ExtendedHeaders(), {},
        tl_vector(QVector<TLftabi_Param>{tl_ftabi_paramTuple(tl_vector(QVector<TLftabi_Param>{
            tl_ftabi_paramBytes(),              // name
            tl_ftabi_paramBytes(),              // symbol
            tl_ftabi_paramUint(tl_int32(8)),    // decimals
            tl_ftabi_paramCell(),               // wallet code
            tl_ftabi_paramUint(tl_int32(256)),  // root_public_key
            tl_ftabi_paramAddress(),            // root_owner_address
            tl_ftabi_paramUint(tl_int32(128)),  // total_supply
            tl_ftabi_paramUint(tl_int32(128)),  // start_gas_balance
            tl_ftabi_paramBool(),               // paused
        }))})));
    Expects(createdFunction.has_value());
    function = createdFunction.value();
  }
  return *function;
}

TLftabi_Function RootTokenGetWalletAddressFunction() {
  static std::optional<TLftabi_function> function;
  if (!function.has_value()) {
    const auto createdFunction = RequestSender::Execute(TLftabi_CreateFunction(  //
        tl_string("getWalletAddress"), ExtendedHeaders(),
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
    const auto createdFunction = RequestSender::Execute(TLftabi_CreateFunction(  //
        tl_string("deployEmptyWallet"), ExtendedHeaders(),
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
    const auto createdFunction = RequestSender::Execute(TLftabi_CreateFunction(  //
        tl_string("balance"), ExtendedHeaders(), {},
        tl_vector(QVector<TLftabi_Param>{tl_ftabi_paramUint(tl_int32(128))})));
    Expects(createdFunction.has_value());
    function = createdFunction.value();
  }
  return *function;
}

TLftabi_Function TokenAcceptFunction() {
  static std::optional<TLftabi_function> function;
  if (!function.has_value()) {
    const auto createdFunction = RequestSender::Execute(TLftabi_CreateFunction(  //
        tl_string("accept"), {},
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
    const auto createdFunction = RequestSender::Execute(TLftabi_CreateFunction(  //
        tl_string("transfer"), {},
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
    const auto createdFunction = RequestSender::Execute(TLftabi_CreateFunction(  //
        tl_string("transferToRecipient"), {},
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
    const auto createdFunction = RequestSender::Execute(TLftabi_CreateFunction(  //
        tl_string("internalTransfer"), {},
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

TLftabi_Function RootTokenContractTokensBurnedFunction() {
  static std::optional<TLftabi_function> function;
  if (!function.has_value()) {
    const auto createdFunction = RequestSender::Execute(TLftabi_CreateFunction(  //
        tl_string("tokensBurned"), {},
        tl_vector(QVector<TLftabi_Param>{
            tl_ftabi_paramUint(tl_int32(128)),  // tokens
            tl_ftabi_paramUint(tl_int32(256)),  // sender_public_key
            tl_ftabi_paramAddress(),            // sender_address
            tl_ftabi_paramAddress(),            // callback_address
            tl_ftabi_paramCell(),               // callback_payload
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
    const auto createdFunction = RequestSender::Execute(TLftabi_CreateFunction(  //
        tl_string("burnByOwner"), {},
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
    const auto createdFunction = RequestSender::Execute(TLftabi_CreateFunction(  //
        tl_string("addOrdinaryStake"), {},
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
    const auto createdFunction = RequestSender::Execute(TLftabi_CreateFunction(  //
        tl_string("addVestingOrLock"), {},
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
    const auto createdFunction = RequestSender::Execute(TLftabi_CreateFunction(  //
        tl_string("withdrawPart"), {},
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
    const auto createdFunction = RequestSender::Execute(TLftabi_CreateFunction(  //
        tl_string("withdrawAll"), {}, {}, {}));
    Expects(createdFunction.has_value());
    function = createdFunction.value();
  }
  return *function;
}

TLftabi_Function DePoolCancelWithdrawalFunction() {
  static std::optional<TLftabi_function> function;
  if (!function.has_value()) {
    const auto createdFunction = RequestSender::Execute(TLftabi_CreateFunction(  //
        tl_string("cancelWithdrawal"), {}, {}, {}));
    Expects(createdFunction.has_value());
    function = createdFunction.value();
  }
  return *function;
}

TLftabi_Function DePoolOnRoundCompleteFunction() {
  static std::optional<TLftabi_function> function;
  if (!function.has_value()) {
    const auto createdFunction = RequestSender::Execute(TLftabi_CreateFunction(  //
        tl_string("onRoundComplete"), {},
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

    const auto createdFunction = RequestSender::Execute(TLftabi_CreateFunction(  //
        tl_string("getParticipantInfo"), DefaultHeaders(),
        tl_vector(QVector<TLftabi_Param>{
            tl_ftabi_paramAddress(),  // addr
        }),
        tl_vector(outputs)));
    Expects(createdFunction.has_value());
    function[withVesting] = createdFunction.value();
  }
  return *function[withVesting];
}

TLftabi_Function MultisigConstructorFunction() {
  static std::optional<TLftabi_function> function;
  if (!function.has_value()) {
    const auto createdFunction = RequestSender::Execute(TLftabi_CreateFunction(  //
        tl_string("constructor"), ExtendedHeaders(),
        tl_vector(QVector<TLftabi_Param>{
            tl_ftabi_paramArray(tl_ftabi_paramUint(tl_int32(256))),  // owners
            tl_ftabi_paramUint(tl_int32(8)),                         // reqConfirms
        }),
        {}));
    Expects(createdFunction.has_value());
    function = createdFunction.value();
  }
  return *function;
}

TLftabi_Function MultisigSubmitTransactionFunction() {
  static std::optional<TLftabi_function> function;
  if (!function.has_value()) {
    const auto createdFunction = RequestSender::Execute(TLftabi_CreateFunction(  //
        tl_string("submitTransaction"), ExtendedHeaders(),
        tl_vector(QVector<TLftabi_Param>{
            tl_ftabi_paramAddress(),            // dest,
            tl_ftabi_paramUint(tl_int32(128)),  // value
            tl_ftabi_paramBool(),               // bounce
            tl_ftabi_paramBool(),               // allBalance
            tl_ftabi_paramCell(),               // payload
        }),
        tl_vector(QVector<TLftabi_Param>{
            tl_ftabi_paramUint(tl_int32(64)),  // transactionId
        })));
    Expects(createdFunction.has_value());
    function = createdFunction.value();
  }
  return *function;
}

TLftabi_Function MultisigConfirmTransactionFunction() {
  static std::optional<TLftabi_function> function;
  if (!function.has_value()) {
    const auto createdFunction = RequestSender::Execute(TLftabi_CreateFunction(  //
        tl_string("confirmTransaction"), ExtendedHeaders(),
        tl_vector(QVector<TLftabi_Param>{
            tl_ftabi_paramUint(tl_int32(64)),  // transactionId
        }),
        {}));
    Expects(createdFunction.has_value());
    function = createdFunction.value();
  }
  return *function;
}

TLftabi_Function MultisigGetParameters(MultisigVersion version) {
  const auto withUpdate = version == MultisigVersion::SetcodeMultisig || version == MultisigVersion::Surf;

  static std::optional<TLftabi_function> function[2];
  if (!function[withUpdate].has_value()) {
    auto outputs = tl_vector(QVector<TLftabi_Param>{
        tl_ftabi_paramUint(tl_int32(8)),    // maxQueuedTransactions
        tl_ftabi_paramUint(tl_int32(8)),    // maxCustodianCount
        tl_ftabi_paramUint(tl_int32(64)),   // expirationTime
        tl_ftabi_paramUint(tl_int32(128)),  // minValue
        tl_ftabi_paramUint(tl_int32(8)),    // requiredTxnConfirms
    });

    if (withUpdate) {
      outputs.v.push_back(tl_ftabi_paramUint(tl_int32(8)));  // requiredUpdConfirms
    }

    const auto createdFunction = RequestSender::Execute(TLftabi_CreateFunction(  //
        tl_string("getParameters"), ExtendedHeaders(), {}, outputs));
    Expects(createdFunction.has_value());
    function[withUpdate] = createdFunction.value();
  }
  return *function[withUpdate];
}

TLftabi_Function MultisigGetTransactionIds() {
  static std::optional<TLftabi_function> function;
  if (!function.has_value()) {
    const auto createdFunction = RequestSender::Execute(TLftabi_CreateFunction(  //
        tl_string("getTransactionIds"), ExtendedHeaders(), {},
        tl_vector(QVector<TLftabi_Param>{
            tl_ftabi_paramArray(tl_ftabi_paramUint(tl_int32(64))),  // ids
        })));
    Expects(createdFunction.has_value());
    function = createdFunction.value();
  }
  return *function;
}

TLftabi_Function MultisigGetCustodians() {
  static std::optional<TLftabi_function> function;
  if (!function.has_value()) {
    const auto createdFunction = RequestSender::Execute(TLftabi_CreateFunction(  //
        tl_string("getCustodians"), ExtendedHeaders(), {},
        tl_vector(QVector<TLftabi_Param>{
            tl_ftabi_paramArray(tl_ftabi_paramTuple(tl_vector(QVector<TLftabi_Param>{
                tl_ftabi_paramUint(tl_int32(8)),    // index
                tl_ftabi_paramUint(tl_int32(256)),  // pubkey
            }))),
        })));
    Expects(createdFunction.has_value());
    function = createdFunction.value();
  }
  return *function;
}

std::optional<QByteArray> ParseTransferComment(const QByteArray &body) {
  const auto decoded = RequestSender::Execute(TLftabi_UnpackFromCell(
      tl_tvm_cell(tl_bytes(body)),
      tl_vector(QVector<TLftabi_Param>{tl_ftabi_paramUint(tl_int32(32)), tl_ftabi_paramBytes()})));
  if (!decoded.has_value()) {
    return std::nullopt;
  }

  const auto args = decoded.value().c_ftabi_decodedOutput().vvalues().v;
  if (args.size() != 2 || !IsBytes(args[1])) {
    return std::nullopt;
  }

  return UnpackBytes(args[1]);
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

std::optional<EthEventStatus> ParseEthEventStatus(const TLftabi_Value &value) {
  if (!IsInt(value)) {
    return std::nullopt;
  }
  switch (value.c_ftabi_valueInt().vvalue().v) {
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

std::optional<EthEventStatus> ParseEthEventNotification(const QByteArray &body) {
  const auto decodedNotification =
      RequestSender::Execute(TLftabi_DecodeInput(EthEventStatusChangedNotification(), tl_bytes(body), tl_boolTrue()));
  if (!decodedNotification.has_value()) {
    return std::nullopt;
  }

  const auto args = decodedNotification.value().c_ftabi_decodedInput().vvalues().v;
  if (args.size() != 1) {
    return std::nullopt;
  }
  return ParseEthEventStatus(args[0]);
}

std::optional<TonEventStatus> ParseTonEventStatus(const TLftabi_Value &value) {
  if (!IsInt(value)) {
    return std::nullopt;
  }
  switch (value.c_ftabi_valueInt().vvalue().v) {
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

std::optional<TonEventStatus> ParseTonEventNotification(const QByteArray &body) {
  const auto decodedNotification =
      RequestSender::Execute(TLftabi_DecodeInput(TonEventStatusChangedNotification(), tl_bytes(body), tl_boolTrue()));
  if (!decodedNotification.has_value()) {
    return std::nullopt;
  }

  const auto args = decodedNotification.value().c_ftabi_decodedInput().vvalues().v;
  if (args.size() != 1) {
    return std::nullopt;
  }
  return ParseTonEventStatus(args[0]);
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

  const auto &args = decodedSwapBackInput.value().c_ftabi_decodedInput().vvalues().v;
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

std::optional<MultisigDeploymentTransaction> ParseMultisigDeploymentTransaction(const QByteArray &body) {
  const auto decoded =
      RequestSender::Execute(TLftabi_DecodeInput(MultisigConstructorFunction(), tl_bytes(body), tl_boolFalse()));
  if (!decoded.has_value()) {
    return std::nullopt;
  }

  // TODO: decode
  return MultisigDeploymentTransaction{};
}

std::optional<MultisigSubmitTransaction> ParseMultisigSubmitTransaction(const QByteArray &body) {
  const auto decoded =
      RequestSender::Execute(TLftabi_DecodeInput(MultisigSubmitTransactionFunction(), tl_bytes(body), tl_boolFalse()));
  if (!decoded.has_value()) {
    return std::nullopt;
  }

  const auto &args = decoded.value().c_ftabi_decodedInput().vvalues().v;
  if (args.size() != 5 || !IsBigInt(args[1]) || !IsBool(args[2]) || !IsCell(args[4])) {
    return std::nullopt;
  }

  const auto &payload = args[4].c_ftabi_valueCell().vvalue().c_tvm_cell().vbytes();

  return MultisigSubmitTransaction{
      .dest = UnpackAddress(args[0]),
      .amount = UnpackUint(args[1]),
      .bounce = UnpackBool(args[2]),
      .comment = ParseTransferComment(payload.v).value_or(QByteArray{}),
  };
}

std::optional<int64> ParseMultisigSubmitTransactionId(const QByteArray &body) {
  const auto decoded =
      RequestSender::Execute(TLftabi_DecodeOutput(MultisigSubmitTransactionFunction(), tl_bytes(body)));
  if (!decoded.has_value()) {
    return std::nullopt;
  }

  const auto &args = decoded.value().c_ftabi_decodedOutput().vvalues().v;
  if (args.size() != 1 || !IsInt(args[0])) {
    return std::nullopt;
  }

  return UnpackUint(args[0]);
}

std::optional<MultisigConfirmTransaction> ParseMultisigConfirmTransaction(const QByteArray &body) {
  const auto decoded =
      RequestSender::Execute(TLftabi_DecodeInput(MultisigConfirmTransactionFunction(), tl_bytes(body), tl_boolFalse()));
  if (!decoded.has_value()) {
    return std::nullopt;
  }

  const auto &args = decoded.value().c_ftabi_decodedInput().vvalues().v;
  if (args.size() != 1 || !IsInt(args[0])) {
    return std::nullopt;
  }

  return MultisigConfirmTransaction{
      .transactionId = UnpackUint(args[0]),
  };
}

std::optional<DePoolOrdinaryStakeTransaction> ParseOrdinaryStakeTransfer(const QByteArray &body) {
  const auto decodedInput =
      RequestSender::Execute(TLftabi_DecodeInput(OrdinaryStakeFunction(), tl_bytes(body), tl_boolTrue()));
  if (!decodedInput.has_value()) {
    return std::nullopt;
  }

  const auto &args = decodedInput.value().c_ftabi_decodedInput().vvalues().v;
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

  const auto &args = decodedInput.value().c_ftabi_decodedInput().vvalues().v;
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
                                                                  const TLftabi_tvmOutput &result) {
  const auto &output = result.c_ftabi_tvmOutput();
  if (output.vexit_code().v != 0) {
    return DePoolParticipantState{.version = dePoolVersion};
  }

  const auto &results = output.vvalues().v;
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

std::optional<RootTokenContractDetails> ParseRootTokenContractDetails(const TLVector<TLftabi_Value> &values) {
  const auto &tokens = values.v;
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

std::optional<TokenWalletContractDetails> ParseTokenWalletContractDetails(const TLVector<TLftabi_Value> &values) {
  const auto &tokens = values.v;
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

void CreateTokenMessage(RequestSender &lib, const QString &recipient, const int128 &amount,
                        const MessageBodyCallback &done) {
  CreateInternalMessageBody(  //
      lib, TokenTransferFunction(),
      {
          PackAddress(recipient),  // to
          PackUint128(amount),     // amount
          PackUint128(),           // grams
      },
      done);
}

void CreateTokenTransferToOwnerMessage(RequestSender &lib, const QString &recipient, const int128 &amount,
                                       int64 deployGrams, const MessageBodyCallback &done) {
  CreateInternalMessageBody(  //
      lib, TokenTransferToOwnerFunction(),
      {
          PackPubKey(),              // recipient_public_key
          PackAddress(recipient),    // recipient_address
          PackUint128(amount),       // tokens
          PackUint128(deployGrams),  // deploy_grams
          PackUint128(),             // transfer_grams
      },
      done);
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

void CreateSwapBackMessage(RequestSender &lib, QByteArray ethereumAddress, const QString &callback_address,
                           const int128 &amount, const MessageBodyCallback &done) {
  Expects(ethereumAddress.size() == kEthereumAddressByteCount);
  ethereumAddress.prepend(32 - kEthereumAddressByteCount, 0);

  auto callback_payload = RequestSender::Execute(TLftabi_PackIntoCell(tl_vector(
      QVector<TLftabi_Value>{tl_ftabi_valueBigInt(tl_ftabi_paramUint(tl_int32(160)), tl_bytes(ethereumAddress))})));
  if (!callback_payload.has_value()) {
    return InvokeCallback(done, callback_payload.error());
  }

  CreateInternalMessageBody(  //
      lib, TokenSwapBackFunction(),
      {
          PackUint128(amount),                 // tokens
          PackUint128(),                       // grams
          PackAddress(callback_address),       // callback_address
          PackCell(callback_payload.value()),  // callback_payload
      },
      done);
}

void CreateStakeMessage(RequestSender &lib, int64 stake, const MessageBodyCallback &done) {
  CreateInternalMessageBody(  //
      lib, OrdinaryStakeFunction(),
      {
          tl_ftabi_valueInt(tl_ftabi_paramUint(tl_int32(64)),
                            tl_int64(stake)),  // stake
      },
      done);
}

void CreateWithdrawalMessage(RequestSender &lib, int64 amount, bool all, const MessageBodyCallback &done) {
  if (all) {
    CreateInternalMessageBody(lib, DePoolWithdrawAllFunction(), {}, done);
  } else {
    CreateInternalMessageBody(  //
        lib, DePoolWithdrawPartFunction(),
        {
            tl_ftabi_valueInt(tl_ftabi_paramUint(tl_int32(64)),
                              tl_int64(amount)),  // withdrawValue
        },
        done);
  }
}

void CreateCancelWithdrawalMessage(RequestSender &lib, const MessageBodyCallback &done) {
  CreateInternalMessageBody(lib, DePoolCancelWithdrawalFunction(), {}, done);
}

void CreateTokenWalletDeployMessage(RequestSender &lib, int64 grams, const QString &owner,
                                    const MessageBodyCallback &done) {
  CreateInternalMessageBody(  //
      lib, RootTokenDeployWalletFunction(),
      {
          PackUint128(grams),
          PackPubKey(),
          PackAddress(owner),
          PackAddress(owner),
      },
      done);
}

void CreateExecuteProxyCallbackMessage(RequestSender &lib, const MessageBodyCallback &done) {
  CreateInternalMessageBody(lib, ExecuteProxyCallbackFunction(), {}, done);
}

QByteArray GetMultisigTvc(Ton::MultisigVersion version) {
  switch (version) {
    case Ton::MultisigVersion::SafeMultisig:
      return LoadSlice(SAFE_MULTISIG_WALLET_TVC);
    case Ton::MultisigVersion::SafeMultisig24h:
      return LoadSlice(SAFE_MULTISIG_24H_WALLET_TVC);
    case Ton::MultisigVersion::SetcodeMultisig:
      return LoadSlice(SETCODE_MULTISIG_WALLET_TVC);
    case Ton::MultisigVersion::Surf:
      return LoadSlice(SURF_TVC);
    default:
      Unexpected("Multisig version");
  }
}

Result<GeneratedInitData> CreateMultisigInitData(Ton::MultisigVersion version, const QByteArray &publicKey) {
  auto tvc = GetMultisigTvc(version);

  const auto raw = RequestSender::Execute(TLftabi_UnpackPublicKey(tl_bytes(publicKey)));
  if (!raw.has_value()) {
    return raw.error();
  }

  const auto result =
      RequestSender::Execute(TLftabi_GenerateStateInit(tl_bytes(tvc), raw->c_ftabi_unpackedPublicKey().vpublic_key()));
  if (!result.has_value()) {
    return result.error();
  }

  const auto &initData = result.value().c_ftabi_stateInit();
  return GeneratedInitData{
      .hash = initData.vhash().v,
      .data = initData.vdata().v,
  };
}

void CreateMultisigConstructorMessage(RequestSender &lib, const TLInputKey &deployerKey, uint8 requiredConfirmations,
                                      const std::vector<QByteArray> &owners, const MessageBodyCallback &done) {
  QVector<TLftabi_Value> packedOwners;
  packedOwners.reserve(owners.size());
  for (const auto &owner : owners) {
    packedOwners.push_back(tl_ftabi_valueBigInt(tl_ftabi_paramUint(tl_int32(256)), tl_bytes(owner)));
  }

  CreateExternalSignedMessageBody(  //
      lib, MultisigConstructorFunction(),
      {
          tl_ftabi_valueArray(tl_ftabi_paramArray(tl_ftabi_paramUint(tl_int32(256))),
                              tl_vector(packedOwners)),                                         // owners
          tl_ftabi_valueInt(tl_ftabi_paramUint(tl_int32(8)), tl_int64(requiredConfirmations)),  // reqConfirms
      },
      deployerKey, done);
}

void CreateMultisigSubmitTransactionMessage(RequestSender &lib, const TLInputKey &key, const QString &dest, int64 value,
                                            bool bounce, const QByteArray &payload, const MessageBodyCallback &done) {
  CreateExternalSignedMessageBody(  //
      lib, MultisigSubmitTransactionFunction(),
      {
          PackAddress(dest),                         // dest
          PackUint128(value),                        // value
          PackBool(bounce),                          // bounce
          PackBool(false),                           // allBalance
          PackCell(tl_tvm_cell(tl_bytes(payload))),  // payload
      },
      key, done);
}

void CreateMultisigConfirmTransactionMessage(RequestSender &lib, const TLInputKey &key, int64 transactionId,
                                             const MessageBodyCallback &done) {
  CreateExternalSignedMessageBody(  //
      lib, MultisigConfirmTransactionFunction(),
      {
          PackUint64(transactionId),  // transactionId
      },
      key, done);
}

const QRegExp &Base64Regex() {
  static const QRegExp regex(R"##(^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$)##");
  return regex;
}

QByteArray PackValuesIntoCell(QVector<TLftabi_Value> &&values) {
  auto result = RequestSender::Execute(TLftabi_PackIntoCell(tl_vector(std::forward<QVector<TLftabi_Value>>(values))));
  if (result.has_value()) {
    return result->c_tvm_cell().vbytes().v;
  } else {
    return {};
  }
}

QByteArray CreatePayloadFromComment(const QString &comment) {
  if (comment.isEmpty()) {
    return {};
  }
  if (Base64Regex().exactMatch(comment)) {
    auto raw = QByteArray::fromBase64(comment.toUtf8());
    if (RequestSender::Execute(
            TLftabi_UnpackFromCell(tl_tvm_cell(tl_bytes(comment.toUtf8())), tl_vector(QVector<TLftabi_Param>{})))
            .has_value()) {
      return raw;
    }
  }
  return PackValuesIntoCell({
      tl_ftabi_valueInt(tl_ftabi_paramUint(tl_int32(32)), tl_int64(0x00000000u)),
      tl_ftabi_valueBytes(tl_ftabi_paramBytes(), tl_bytes(comment.toUtf8())),
  });
}

}  // namespace Ton::details
