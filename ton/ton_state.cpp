// This file is part of Desktop App Toolkit,
// a set of libraries for developing nice desktop applications.
//
// For license and copyright information please follow this link:
// https://github.com/desktop-app/legal/blob/master/LEGAL
//
#include "ton/ton_state.h"

#include <QHash>

namespace std {
template<> struct hash<QString> {
	std::size_t operator()(const QString& s) const noexcept {
		return static_cast<size_t>(qHash(s));
	}
};
}

namespace Ton {

QString toString(TokenKind token) {
	static std::unordered_map<TokenKind, QString> kindToName = {
		{TokenKind::Ton, "TON"},
		{TokenKind::USDT, "USDT"},
		{TokenKind::USDC, "USDC"},
		{TokenKind::DAI, "DAI"},
		{TokenKind::WBTC, "WBTC"},
		{TokenKind::WETH, "WETH"}
	};
	const auto it = kindToName.find(token);
	if (it == kindToName.end()) {
		return "unknown";
	} else {
		return it->second;
	}
}

TokenKind tokenFromString(const QString &token) {
	static std::unordered_map<QString, TokenKind> nameToKind = {
		{"ton", TokenKind::Ton},
		{"usdt", TokenKind::USDT},
		{"usdc", TokenKind::USDC},
		{"dai", TokenKind::DAI},
		{"wbtc", TokenKind::WBTC},
		{"weth", TokenKind::WETH}
	};
	const auto it = nameToKind.find(token.toLower());
	if (it == nameToKind.end()) {
		return TokenKind::DefaultToken;
	} else {
		return it->second;
	}
}

uint32_t countDecimals(TokenKind token) {
	static std::unordered_map<TokenKind, uint32_t> kindToDecimals = {
		{TokenKind::Ton, 9},
		{TokenKind::USDT, 6},
		{TokenKind::USDC, 6},
		{TokenKind::DAI, 9},
		{TokenKind::WBTC, 8},
		{TokenKind::WETH, 9}
	};
	const auto it = kindToDecimals.find(token);
	if (it == kindToDecimals.end()) {
		return 1;
	} else {
		return it->second;
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
