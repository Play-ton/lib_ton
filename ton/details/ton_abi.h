#pragma once

#include "ton/details/ton_tl_core.h"
#include "ton/ton_result.h"

#include <boost/multiprecision/cpp_int.hpp>

namespace tl {
template <typename>
class boxed;
}  // namespace tl

namespace Ton {

using int128 = boost::multiprecision::int128_t;

struct InvestParams;
struct TokenTransfer;
struct TokenMint;

enum class EthEventStatus;
enum class TonEventStatus;
struct TokenWalletDeployed;
struct TokenSwapBack;

struct DePoolOrdinaryStakeTransaction;
struct DePoolOnRoundCompleteTransaction;
struct DePoolParticipantState;

struct RootTokenContractDetails;
struct TokenWalletContractDetails;

}  // namespace Ton

namespace Ton::details {

class TLftabi_value;
class TLtvm_cell;
class TLftabi_namedParam;
class TLDftabi_valueMap;
class TLftabi_function;
class TLftabi_decodedOutput;
class TLftabi_tvmOutput;

template <typename T>
using TLVector = tl::boxed<TLvector<T>>;
using TLftabi_Value = tl::boxed<TLftabi_value>;
using TLtvm_Cell = tl::boxed<TLtvm_cell>;
using TLftabi_Function = tl::boxed<TLftabi_function>;

[[nodiscard]] TLftabi_Value PackPubKey();

[[nodiscard]] int128 UnpackUint128(const TLftabi_Value &value);
[[nodiscard]] TLftabi_Value PackUint128(int64 value);
[[nodiscard]] TLftabi_Value PackUint128(const int128 &value);
[[nodiscard]] TLftabi_Value PackUint128();

[[nodiscard]] int64 UnpackUint(const TLftabi_Value &value);

[[nodiscard]] QString UnpackAddress(const TLftabi_Value &value);
[[nodiscard]] TLftabi_Value PackAddress(const QString &value);

[[nodiscard]] TLftabi_Value PackCell(const TLtvm_Cell &value);

[[nodiscard]] bool UnpackBool(const TLftabi_Value &value);

[[nodiscard]] QByteArray UnpackBytes(const TLftabi_Value &value);

bool IsAddress(const TLftabi_Value &value);
bool IsInt(const TLftabi_Value &value);
bool IsBigInt(const TLftabi_Value &value);
bool IsBool(const TLftabi_Value &value);
bool IsCell(const TLftabi_Value &value);

[[nodiscard]] TLVector<TLftabi_namedParam> DefaultHeaders();
[[nodiscard]] TLVector<TLftabi_namedParam> ExtendedHeaders();

[[nodiscard]] std::map<int64, InvestParams> parseInvestParamsMap(const TLDftabi_valueMap &map);

[[nodiscard]] TLftabi_Function EthEventStatusChangedNotification();
[[nodiscard]] TLftabi_Function TonEventStatusChangedNotification();
[[nodiscard]] TLftabi_Function TokenWalletDeployedNotification();

[[nodiscard]] TLftabi_Function EthEventGetDetailsFunction();
[[nodiscard]] TLftabi_Function EthEventGetDecodedDataFunction();
[[nodiscard]] TLftabi_Function TonEventGetDetailsFunction();
[[nodiscard]] TLftabi_Function TonEventGetDecodedDataFunction();

[[nodiscard]] TLftabi_Function TokenWalletGetDetailsFunction();

[[nodiscard]] TLftabi_Function RootTokenGetDetailsFunction();
[[nodiscard]] TLftabi_Function RootTokenGetWalletAddressFunction();
[[nodiscard]] TLftabi_Function RootTokenDeployWalletFunction();

[[nodiscard]] TLftabi_Function ExecuteProxyCallbackFunction();

[[nodiscard]] TLftabi_Function TokenGetBalanceFunction();
[[nodiscard]] TLftabi_Function TokenAcceptFunction();
[[nodiscard]] TLftabi_Function TokenTransferFunction();
[[nodiscard]] TLftabi_Function TokenTransferToOwnerFunction();
[[nodiscard]] TLftabi_Function TokenInternalTransferFunction();

[[nodiscard]] TLftabi_Function RootTokenContractTokensBurnedFunction();

[[nodiscard]] TLftabi_Function TokenSwapBackFunction();

[[nodiscard]] TLftabi_Function OrdinaryStakeFunction();
[[nodiscard]] TLftabi_Function VestingOrLockStakeFunction();
[[nodiscard]] TLftabi_Function DePoolWithdrawPartFunction();
[[nodiscard]] TLftabi_Function DePoolWithdrawAllFunction();
[[nodiscard]] TLftabi_Function DePoolCancelWithdrawalFunction();
[[nodiscard]] TLftabi_Function DePoolOnRoundCompleteFunction();
[[nodiscard]] TLftabi_Function DePoolParticipantInfoFunction(int32 dePoolVersion);

[[nodiscard]] TLftabi_Function MultisigConstructorFunction();

[[nodiscard]] std::optional<TokenTransfer> ParseTokenTransfer(const QByteArray &body);
[[nodiscard]] std::optional<TokenTransfer> ParseTokenTransferToOwner(const QByteArray &body);
[[nodiscard]] std::optional<TokenTransfer> ParseInternalTokenTransfer(const QByteArray &body);
[[nodiscard]] std::optional<TokenMint> ParseTokenAccept(const QByteArray &body);
[[nodiscard]] std::optional<EthEventStatus> ParseEthEventStatus(const TLftabi_Value &value);
[[nodiscard]] std::optional<EthEventStatus> ParseEthEventNotification(const QByteArray &body);
[[nodiscard]] std::optional<TonEventStatus> ParseTonEventStatus(const TLftabi_Value &value);
[[nodiscard]] std::optional<TonEventStatus> ParseTonEventNotification(const QByteArray &body);
[[nodiscard]] std::optional<TokenWalletDeployed> ParseTokenWalletDeployedNotification(const QByteArray &body);
[[nodiscard]] std::optional<TokenSwapBack> ParseTokenSwapBack(const QByteArray &body);

[[nodiscard]] std::optional<DePoolOrdinaryStakeTransaction> ParseOrdinaryStakeTransfer(const QByteArray &body);
[[nodiscard]] std::optional<DePoolOnRoundCompleteTransaction> ParseDePoolOnRoundComplete(const QByteArray &body);

[[nodiscard]] std::optional<DePoolParticipantState> ParseDePoolParticipantState(int32 dePoolVersion,
                                                                                const TLftabi_tvmOutput &result);

[[nodiscard]] std::optional<RootTokenContractDetails> ParseRootTokenContractDetails(
    const TLVector<TLftabi_Value> &values);
[[nodiscard]] std::optional<TokenWalletContractDetails> ParseTokenWalletContractDetails(
    const TLVector<TLftabi_Value> &values);

[[nodiscard]] Result<QByteArray> CreateTokenMessage(const QString &recipient, const int128 &amount);
[[nodiscard]] Result<QByteArray> CreateTokenTransferToOwnerMessage(const QString &recipient, const int128 &amount,
                                                                   int64 deployGrams);

[[nodiscard]] std::optional<QByteArray> ParseEthereumAddress(const QString &ethereumAddress);
[[nodiscard]] Result<QByteArray> CreateSwapBackMessage(QByteArray ethereumAddress, const QString &callback_address,
                                                       const int128 &amount);

[[nodiscard]] Result<QByteArray> CreateStakeMessage(int64 stake);
[[nodiscard]] Result<QByteArray> CreateWithdrawalMessage(int64 amount, bool all);
[[nodiscard]] Result<QByteArray> CreateCancelWithdrawalMessage();

[[nodiscard]] Result<QByteArray> CreateTokenWalletDeployMessage(int64 grams, const QString &owner);
[[nodiscard]] Result<QByteArray> CreateExecuteProxyCallbackMessage();

struct GeneratedInitData {
  QByteArray hash;
  QByteArray data;
};

[[nodiscard]] Result<GeneratedInitData> CreateMultisigInitData(QByteArray publicKey);
[[nodiscard]] Result<QByteArray> CreateMultisigConstructorMessage(const QByteArray &deployerPublicKey,
                                                                  const QByteArray &deployerPrivateKey,
                                                                  uint8 requiredConfirmations,
                                                                  const std::vector<QByteArray> &owners);

}  // namespace Ton::details
