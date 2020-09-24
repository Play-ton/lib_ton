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

struct TokenInfo {
	QString symbol{};
	int64 decimals{};
	QString contract{};
};

TokenInfo* FindTokenInfo(TokenKind token) {
	static std::unordered_map<TokenKind, TokenInfo> kindToInfo = {
		{TokenKind::Ton,  { .symbol = "TON", .decimals = 9 }},
		{TokenKind::USDT, { .symbol = "USDT", .decimals = 6, .contract = "0xdac17f958d2ee523a2206206994597c13d831ec7" }},
		{TokenKind::USDC, { .symbol = "USDC", .decimals = 6, .contract = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48" }},
		{TokenKind::DAI,  { .symbol = "DAI", .decimals = 9, .contract = "0x6b175474e89094c44da98b954eedeac495271d0f" }},
		{TokenKind::WBTC, { .symbol = "WBTC", .decimals = 8, .contract = "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599" }},
		{TokenKind::WETH, { .symbol = "WETH", .decimals = 9, .contract = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2" }},
	};
	const auto it = kindToInfo.find(token);
	if (it != kindToInfo.end()) {
		return &it->second;
	} else {
		return nullptr;
	}
}

QString toString(TokenKind token) {
	if (const auto* info = FindTokenInfo(token)) {
		return info->symbol;
	} else {
		return "unknown";
	}
}

uint32_t countDecimals(TokenKind token) {
	if (const auto* info = FindTokenInfo(token)) {
		return info->decimals;
	} else {
		return 1;
	}
}

QString contractAddress(TokenKind token) {
	if (const auto* info = FindTokenInfo(token)) {
		return info->contract;
	} else {
		return {};
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
