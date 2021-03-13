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

struct MultisigDeploymentTransaction;
struct MultisigSubmitTransaction;
struct MultisigConfirmTransaction;

enum class MultisigVersion;

}  // namespace Ton

namespace Ton::details {

class TLftabi_value;
class TLtvm_cell;
class TLftabi_namedParam;
class TLDftabi_valueMap;
class TLftabi_function;
class TLftabi_decodedOutput;
class TLftabi_tvmOutput;
class TLinputKey;

template <typename T>
using TLVector = tl::boxed<TLvector<T>>;
using TLtvm_Cell = tl::boxed<TLtvm_cell>;
using TLftabi_Value = tl::boxed<TLftabi_value>;
using TLftabi_Function = tl::boxed<TLftabi_function>;
using TLInputKey = tl::boxed<TLinputKey>;

class RequestSender;

[[nodiscard]] QByteArray UnpackPubkey(const TLftabi_Value &value);
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
bool IsBytes(const TLftabi_Value &value);
bool IsCell(const TLftabi_Value &value);

[[nodiscard]] TLVector<TLftabi_namedParam> DefaultHeaders();
[[nodiscard]] TLVector<TLftabi_namedParam> ExtendedHeaders();

[[nodiscard]] std::map<int64, InvestParams> parseInvestParamsMap(const TLDftabi_valueMap &map);

[[nodiscard]] TLftabi_Function TransferWithComment();

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
[[nodiscard]] TLftabi_Function MultisigSubmitTransactionFunction();
[[nodiscard]] TLftabi_Function MultisigConfirmTransactionFunction();
[[nodiscard]] TLftabi_Function MultisigGetParameters(MultisigVersion version);
[[nodiscard]] TLftabi_Function MultisigGetTransactionIds();
[[nodiscard]] TLftabi_Function MultisigGetCustodians();

[[nodiscard]] std::optional<QByteArray> ParseTransferComment(const QByteArray &body);
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
[[nodiscard]] std::optional<MultisigDeploymentTransaction> ParseMultisigDeploymentTransaction(const QByteArray &body);
[[nodiscard]] std::optional<MultisigSubmitTransaction> ParseMultisigSubmitTransaction(const QByteArray &body);
[[nodiscard]] std::optional<int64> ParseMultisigSubmitTransactionId(const QByteArray &body);
[[nodiscard]] std::optional<MultisigConfirmTransaction> ParseMultisigConfirmTransaction(const QByteArray &body);

[[nodiscard]] std::optional<DePoolOrdinaryStakeTransaction> ParseOrdinaryStakeTransfer(const QByteArray &body);
[[nodiscard]] std::optional<DePoolOnRoundCompleteTransaction> ParseDePoolOnRoundComplete(const QByteArray &body);

[[nodiscard]] std::optional<DePoolParticipantState> ParseDePoolParticipantState(int32 dePoolVersion,
                                                                                const TLftabi_tvmOutput &result);

[[nodiscard]] std::optional<RootTokenContractDetails> ParseRootTokenContractDetails(
    const TLVector<TLftabi_Value> &values);
[[nodiscard]] std::optional<TokenWalletContractDetails> ParseTokenWalletContractDetails(
    const TLVector<TLftabi_Value> &values);

using MessageBodyCallback = Callback<QByteArray>;

void CreateTokenMessage(RequestSender &lib, const QString &recipient, const int128 &amount,
                        const MessageBodyCallback &done);
void CreateTokenTransferToOwnerMessage(RequestSender &lib, const QString &recipient, const int128 &amount,
                                       int64 deployGrams, const MessageBodyCallback &done);

[[nodiscard]] std::optional<QByteArray> ParseEthereumAddress(const QString &ethereumAddress);
void CreateSwapBackMessage(RequestSender &lib, QByteArray ethereumAddress, const QString &callback_address,
                           const int128 &amount, const MessageBodyCallback &done);

void CreateStakeMessage(RequestSender &lib, int64 stake, const MessageBodyCallback &done);
void CreateWithdrawalMessage(RequestSender &lib, int64 amount, bool all, const MessageBodyCallback &done);
void CreateCancelWithdrawalMessage(RequestSender &lib, const MessageBodyCallback &done);

void CreateTokenWalletDeployMessage(RequestSender &lib, int64 grams, const QString &owner,
                                    const MessageBodyCallback &done);
void CreateExecuteProxyCallbackMessage(RequestSender &lib, const MessageBodyCallback &done);

struct GeneratedInitData {
  QByteArray hash;
  QByteArray data;
};

[[nodiscard]] Result<GeneratedInitData> CreateMultisigInitData(Ton::MultisigVersion version,
                                                               const QByteArray &publicKey);
void CreateMultisigConstructorMessage(RequestSender &lib, const TLInputKey &deployerKey, uint8 requiredConfirmations,
                                      const std::vector<QByteArray> &owners, const MessageBodyCallback &done);
void CreateMultisigSubmitTransactionMessage(RequestSender &lib, const TLInputKey &key, const QString &dest, int64 value,
                                            bool bounce, const QByteArray &payload, const MessageBodyCallback &done);
void CreateMultisigConfirmTransactionMessage(RequestSender &lib, const TLInputKey &key, int64 transactionId,
                                             const MessageBodyCallback &done);

}  // namespace Ton::details
