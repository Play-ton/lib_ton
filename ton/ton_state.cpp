// This file is part of Desktop App Toolkit,
// a set of libraries for developing nice desktop applications.
//
// For license and copyright information please follow this link:
// https://github.com/desktop-app/legal/blob/master/LEGAL
//
#include "ton/ton_state.h"

namespace Ton {

QString toString(TokenKind token) {
	switch (token) {
		case TokenKind::Ton:
			return "TON";
		case TokenKind::USDT:
			return "USDT";
		default:
			return "unknown";
	}
}

TokenKind tokenFromString(QString token) {
    if (token == "TON") {
        return TokenKind::Ton;
    } else if (token == "USDT") {
        return TokenKind::USDT;
    }
    return TokenKind::DefaultToken;
}

uint32_t countDecimals(TokenKind token) {
	switch (token) {
		case TokenKind::Ton:
			return 9;
		case TokenKind::USDT:
			return 6;
		default:
			return 1;
	}
}

bool operator!(const TokenKind &token) {
	return token == Ton::TokenKind::Ton;
}

bool operator<(const TransactionId &a, const TransactionId &b) {
	return (a.lt < b.lt);
}

bool operator==(const TransactionId &a, const TransactionId &b) {
	return (a.lt == b.lt);
}

bool operator!=(const TransactionId &a, const TransactionId &b) {
	return !(a == b);
}

bool operator==(const TokenState &a, const TokenState &b) {
	return (a.token == b.token) && (a.fullBalance == b.fullBalance);
}

bool operator!=(const TokenState &a, const TokenState &b) {
	return (a.token != b.token) || (a.fullBalance != b.fullBalance);
}

bool CheckTokenTransaction(TokenKind token, const TokenTransaction& transaction) {
	return v::match(transaction, [&](const TokenTransfer &transfer) {
		return transfer.token == token;
	}, [&](const TokenSwapBack &swapBack) {
		return swapBack.token == token;
	});
}

bool operator==(const RestrictionLimit &a, const RestrictionLimit &b) {
	return (a.seconds == b.seconds) && (a.lockedAmount == b.lockedAmount);
}
bool operator!=(const RestrictionLimit &a, const RestrictionLimit &b) {
	return !(a == b);
}

bool operator==(const AccountState &a, const AccountState &b) {
	return (a.fullBalance == b.fullBalance)
		&& (a.lockedBalance == b.lockedBalance)
		&& (a.lastTransactionId == b.lastTransactionId)
		&& (a.restrictionLimits == b.restrictionLimits);
}

bool operator!=(const AccountState &a, const AccountState &b) {
	return !(a == b);
}

bool operator==(const Transaction &a, const Transaction &b) {
	return (a.id == b.id)
		|| ((a.incoming.bodyHash == b.incoming.bodyHash)
			&& (!a.id.lt || !b.id.lt));
}

bool operator!=(const Transaction &a, const Transaction &b) {
	return !(a == b);
}

bool operator==(const TransactionsSlice &a, const TransactionsSlice &b) {
	return (a.list == b.list) && (a.previousId == b.previousId);
}

bool operator!=(const TransactionsSlice &a, const TransactionsSlice &b) {
	return !(a == b);
}

bool operator==(const PendingTransaction &a, const PendingTransaction &b) {
	return (a.fake == b.fake)
		&& (a.sentUntilSyncTime == b.sentUntilSyncTime);
}

bool operator!=(const PendingTransaction &a, const PendingTransaction &b) {
	return !(a == b);
}

bool operator==(const WalletState &a, const WalletState &b) {
	return (a.address == b.address)
		&& (a.account == b.account)
		&& (a.lastTransactions == b.lastTransactions)
		&& (a.pendingTransactions == b.pendingTransactions)
		&& (a.tokenStates == b.tokenStates);
}

bool operator!=(const WalletState &a, const WalletState &b) {
	return !(a == b);
}

int64 TransactionFees::sum() const {
	return inForward + forward + storage + gas;
}

bool SyncState::valid() const {
	return (from <= current) && (current <= to) && (from < to);
}

bool operator==(const SyncState &a, const SyncState &b) {
	if (!a.valid()) {
		return !b.valid();
	}
	return (a.from == b.from) && (a.to == b.to) && (a.current == b.current);
}

bool operator!=(const SyncState &a, const SyncState &b) {
	return !(a == b);
}

} // namespace Ton
