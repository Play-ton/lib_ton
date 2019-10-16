// This file is part of Desktop App Toolkit,
// a set of libraries for developing nice desktop applications.
//
// For license and copyright information please follow this link:
// https://github.com/desktop-app/legal/blob/master/LEGAL
//
#include "ton/ton_state.h"

namespace Ton {

bool operator<(const TransactionId &a, const TransactionId &b) {
	return (a.id < b.id);
}

bool operator==(const TransactionId &a, const TransactionId &b) {
	return (a.id == b.id);
}

bool operator!=(const TransactionId &a, const TransactionId &b) {
	return !(a == b);
}

bool operator==(const AccountState &a, const AccountState &b) {
	return (a.balance == b.balance)
		&& (a.lastTransactionId == b.lastTransactionId);
}

bool operator!=(const AccountState &a, const AccountState &b) {
	return !(a == b);
}

bool operator==(const Transaction &a, const Transaction &b) {
	return (a.id == b.id) && (a.incoming.bodyHash == b.incoming.bodyHash);
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
		&& (a.pendingTransactions == b.pendingTransactions);
}

bool operator!=(const WalletState &a, const WalletState &b) {
	return !(a == b);
}

int64 TransactionFees::sum() const {
	return inForward + forward + storage + gas;
}

} // namespace Ton
