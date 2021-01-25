// This file is part of Desktop App Toolkit,
// a set of libraries for developing nice desktop applications.
//
// For license and copyright information please follow this link:
// https://github.com/desktop-app/legal/blob/master/LEGAL
//
#include "ton/ton_state.h"

#include <QHash>

namespace Ton {

bool operator==(const Symbol &a, const Symbol &b) {
  return a.kind() == b.kind() && (a.isTon() || a.name() == b.name() && a.decimals() == b.decimals());
}

bool operator!=(const Symbol &a, const Symbol &b) {
  return !(a == b);
}

bool operator<(const Symbol &a, const Symbol &b) {
  return a.isTon() ||
         a.isToken() && b.isToken() && (a.name() < b.name() || a.name() == b.name() && a.decimals() < b.decimals());
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
  return (a.token == b.token) && (a.balance == b.balance) && (a.rootContractAddress == b.rootContractAddress) &&
         (a.walletContractAddress == b.walletContractAddress);
}

bool operator!=(const TokenState &a, const TokenState &b) {
  return !(a == b);
}

bool operator==(const TokenStateValue &a, const TokenStateValue &b) {
  return (a.balance == b.balance) && (a.rootContractAddress == b.rootContractAddress) &&
         (a.walletContractAddress == b.walletContractAddress);
}

bool operator!=(const TokenStateValue &a, const TokenStateValue &b) {
  return !(a == b);
}

bool operator==(const InvestParams &a, const InvestParams &b) {
  return (a.remainingAmount == b.remainingAmount) && (a.lastWithdrawalTime == b.lastWithdrawalTime) &&
         (a.withdrawalPeriod == b.withdrawalPeriod) && (a.withdrawalValue == b.withdrawalValue) && (a.owner == b.owner);
}

bool operator!=(const InvestParams &a, const InvestParams &b) {
  return !(a == b);
}

bool operator==(const DePoolParticipantState &a, const DePoolParticipantState &b) {
  return (a.total == b.total) && (a.withdrawValue == b.withdrawValue) && (a.reinvest == b.reinvest) &&
         (a.reward == b.reward) && (a.vestings == b.vestings) && (a.locks == b.locks);
}

bool operator!=(const DePoolParticipantState &a, const DePoolParticipantState &b) {
  return !(a == b);
}

bool operator==(const RestrictionLimit &a, const RestrictionLimit &b) {
  return (a.seconds == b.seconds) && (a.lockedAmount == b.lockedAmount);
}
bool operator!=(const RestrictionLimit &a, const RestrictionLimit &b) {
  return !(a == b);
}

bool operator==(const AccountState &a, const AccountState &b) {
  return (a.fullBalance == b.fullBalance) && (a.lockedBalance == b.lockedBalance) &&
         (a.lastTransactionId == b.lastTransactionId) && (a.restrictionLimits == b.restrictionLimits);
}

bool operator!=(const AccountState &a, const AccountState &b) {
  return !(a == b);
}

bool operator==(const Transaction &a, const Transaction &b) {
  return (a.id == b.id) || ((a.incoming.bodyHash == b.incoming.bodyHash) && (!a.id.lt || !b.id.lt));
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
  return (a.fake == b.fake) && (a.sentUntilSyncTime == b.sentUntilSyncTime);
}

bool operator!=(const PendingTransaction &a, const PendingTransaction &b) {
  return !(a == b);
}

bool operator==(const WalletState &a, const WalletState &b) {
  return (a.address == b.address) && (a.account == b.account) && (a.lastTransactions == b.lastTransactions) &&
         (a.pendingTransactions == b.pendingTransactions) && (a.tokenStates == b.tokenStates) &&
         (a.dePoolParticipantStates == b.dePoolParticipantStates);
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

}  // namespace Ton
