// This file is part of Desktop App Toolkit,
// a set of libraries for developing nice desktop applications.
//
// For license and copyright information please follow this link:
// https://github.com/desktop-app/legal/blob/master/LEGAL
//
#pragma once

#include "ton/ton_settings.h"

namespace Ton {

inline constexpr auto kUnknownBalance = int64(-666);

struct ConfigInfo {
	int64 walletId = 0;
	QByteArray restrictedInitPublicKey;
};

struct TransactionId {
	int64 lt = 0;
	QByteArray hash;
};

enum class TokenKind {
    DefaultToken = 0x0,
	Ton = 0x0,
	USDT = 0x1,
};

bool operator!(const TokenKind &kind);

template <typename T>
using TokenMap = std::unordered_map<Ton::TokenKind, T>;

QString toString(TokenKind kind);
uint32_t countDecimals(TokenKind kind);

bool operator==(
	const TransactionId &a,
	const TransactionId &b);
bool operator!=(
	const TransactionId &a,
	const TransactionId &b);
bool operator<(
	const TransactionId &a,
	const TransactionId &b);

struct RestrictionLimit {
	int32 seconds = 0;
	int64 lockedAmount = 0;
};

bool operator==(const RestrictionLimit &a, const RestrictionLimit &b);
bool operator!=(const RestrictionLimit &a, const RestrictionLimit &b);

struct AccountState {
	int64 fullBalance = kUnknownBalance;
	int64 lockedBalance = 0;
	int64 syncTime = 0;
	int64 restrictionStartAt = 0;
	TransactionId lastTransactionId;
	std::vector<RestrictionLimit> restrictionLimits;
};

bool operator==(const AccountState &a, const AccountState &b);
bool operator!=(const AccountState &a, const AccountState &b);

struct TokenState {
	TokenKind token;
	int64 fullBalance = kUnknownBalance;
};

bool operator==(const TokenState &a, const TokenState &b);
bool operator!=(const TokenState &a, const TokenState &b);

enum class MessageDataType {
	PlainText,
	EncryptedText,
	DecryptedText,
	RawBody
};

struct TokenTransfer {
	TokenKind token;
	QString dest;
	int64 value = 0;
};

struct TokenSwapBack {
	TokenKind token;
	QString dest;
	int64 value = 0;
};

using TokenTransaction = std::variant<
	TokenTransfer,
	TokenSwapBack>;

struct MessageData {
	QString text;
	QByteArray data;
	MessageDataType type;
};

struct Message {
	QString source;
	QString destination;
	int64 value = 0;
	int64 created = 0;
	QByteArray bodyHash;
	MessageData message;
};

struct EncryptedText {
	QByteArray bytes;
	QString source;
};

struct DecryptedText {
	QString text;
	QByteArray proof;
};

struct Transaction {
	TransactionId id;
	int64 time = 0;
	int64 fee = 0;
	int64 storageFee = 0;
	int64 otherFee = 0;
	Message incoming;
	std::vector<Message> outgoing;
	bool initializing = false;
};

bool operator==(const Transaction &a, const Transaction &b);
bool operator!=(const Transaction &a, const Transaction &b);

struct TransactionsSlice {
	std::vector<Transaction> list;
	TransactionId previousId;
};

bool operator==(
	const TransactionsSlice &a,
	const TransactionsSlice &b);
bool operator!=(
	const TransactionsSlice &a,
	const TransactionsSlice &b);

struct TransactionToSend {
	int64 amount = 0;
	QString recipient;
	QString comment;
	int timeout = 0;
	bool allowSendToUninited = false;
	bool sendUnencryptedText = false;
};

struct TokenTransactionToSend {
	TokenKind token;
	int64 realAmount = 10000000; // default 0.01 TON will be recalculated after check
	int64 amount = 0;
	QString recipient;
	int timeout = 0;
	bool swapBack = false;
	bool allowSendToUninited = false;
};

struct TransactionFees {
	int64 inForward = 0;
	int64 storage = 0;
	int64 gas = 0;
	int64 forward = 0;

	[[nodiscard]] int64 sum() const;
};

struct TransactionCheckResult {
	TransactionFees sourceFees;
	std::vector<TransactionFees> destinationFees;
};

struct PendingTransaction {
	Transaction fake;
	int64 sentUntilSyncTime = 0;
};

bool operator==(
	const PendingTransaction &a,
	const PendingTransaction &b);
bool operator!=(
	const PendingTransaction &a,
	const PendingTransaction &b);

struct WalletState {
	QString address;
	AccountState account;
	TransactionsSlice lastTransactions;
	std::vector<PendingTransaction> pendingTransactions;
	std::unordered_map<TokenKind, TokenState> tokenStates;
};

bool operator==(const WalletState &a, const WalletState &b);
bool operator!=(const WalletState &a, const WalletState &b);

struct WalletViewerState {
	WalletState wallet;
	crl::time lastRefresh = 0;
	bool refreshing = false;
};

struct LoadedSlice {
	TransactionId after;
	TransactionsSlice data;
};

struct SyncState {
	int from = 0;
	int to = 0;
	int current = 0;

	bool valid() const;
};

bool operator==(const SyncState &a, const SyncState &b);
bool operator!=(const SyncState &a, const SyncState &b);

struct LiteServerQuery {
	int64 id = 0;
	QByteArray bytes;
};

struct DecryptPasswordNeeded {
	QByteArray publicKey;
	int generation = 0;
};

struct DecryptPasswordGood {
	int generation = 0;
};

struct TokenContractAddressChanged {
	QString newTokenContractAddress = {};
};

struct Update {
	std::variant<
		SyncState,
		LiteServerQuery,
		ConfigUpgrade,
		DecryptPasswordNeeded,
		DecryptPasswordGood,
		TokenContractAddressChanged> data;
};

} // namespace Ton
