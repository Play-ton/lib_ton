// This file is part of Desktop App Toolkit,
// a set of libraries for developing nice desktop applications.
//
// For license and copyright information please follow this link:
// https://github.com/desktop-app/legal/blob/master/LEGAL
//
#include "ton/ton_state.h"

#include <QHash>

namespace Ton {

const QString kZeroAddress = "0:0000000000000000000000000000000000000000000000000000000000000000";

bool operator==(const Symbol &a, const Symbol &b) {
  return a.kind() == b.kind() && (a.isTon() || (a.name() == b.name() && a.decimals() == b.decimals() &&
                                                a.rootContractAddress() == b.rootContractAddress()));
}

bool operator!=(const Symbol &a, const Symbol &b) {
  return !(a == b);
}

auto Symbol::toString() const -> QString {
  return QString{"%1,%2,%3"}.arg(_name, QString::number(_decimals), _rootContractAddress);
}

auto Symbol::operator<(const Symbol &other) const -> bool {
  return std::tie(_name, _decimals, _rootContractAddress) <
         std::tie(other._name, other._decimals, other._rootContractAddress);
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
  return (a.token == b.token) && (a.balance == b.balance) && (a.lastTransactions == b.lastTransactions) &&
         (a.walletContractAddress == b.walletContractAddress);
}

bool operator!=(const TokenState &a, const TokenState &b) {
  return !(a == b);
}

bool operator==(const TokenStateValue &a, const TokenStateValue &b) {
  return (a.balance == b.balance) && (a.lastTransactions == b.lastTransactions) &&
         (a.walletContractAddress == b.walletContractAddress);
}

bool operator!=(const TokenStateValue &a, const TokenStateValue &b) {
  return !(a == b);
}

bool operator==(const MultisigState &a, const MultisigState &b) {
  return (a.accountState == b.accountState) && (a.lastTransactions == b.lastTransactions);
}

bool operator!=(const MultisigState &a, const MultisigState &b) {
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

bool operator==(const AssetListItem &a, const AssetListItem &b) {
  if (a.index() != b.index()) {
    return false;
  }
  return v::match(
      a, [](const AssetListItemWallet &) { return true; },
      [&](const AssetListItemToken &itemA) {
        const auto *itemB = std::get_if<AssetListItemToken>(&b);
        return itemA.symbol == itemB->symbol;
      },
      [&](const AssetListItemDePool &itemA) {
        const auto *itemB = std::get_if<AssetListItemDePool>(&b);
        return itemA.address == itemB->address;
      });
}

bool operator!=(const AssetListItem &a, const AssetListItem &b) {
  return !(a == b);
}

bool operator==(const WalletState &a, const WalletState &b) {
  return (a.address == b.address) && (a.account == b.account) && (a.lastTransactions == b.lastTransactions) &&
         (a.pendingTransactions == b.pendingTransactions) && (a.tokenStates == b.tokenStates) &&
         (a.dePoolParticipantStates == b.dePoolParticipantStates) && (a.assetsList == b.assetsList);
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

QByteArray Int128ToBytesBE(const int128 &from) {
  QByteArray to(32, 0);

  auto size = from.backend().size() * sizeof(boost::multiprecision::limb_type);
  auto iter = reinterpret_cast<const int8_t *>(from.backend().limbs());

  for (int i = 0; i < size; ++i) {
    to[to.size() - 1 - i] = iter[i];
  }

  return to;
}

int128 BytesBEToInt128(const QByteArray &from) {
  if (from.length() != 32) {
    Unexpected("Array is not a uint256");
  }

  constexpr auto size = 16;

  int128 to = 0;
  uint32_t limbCount = size / sizeof(boost::multiprecision::limb_type);
  to.backend().resize(limbCount, limbCount);

  auto iter = reinterpret_cast<int8_t *>(to.backend().limbs());

  for (int i = 0; i < size; i++) {
    iter[i] = from[from.size() - 1 - i];
  }

  to.backend().normalize();

  return to;
}

}  // namespace Ton
