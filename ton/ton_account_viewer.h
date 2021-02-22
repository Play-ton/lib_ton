// This file is part of Desktop App Toolkit,
// a set of libraries for developing nice desktop applications.
//
// For license and copyright information please follow this link:
// https://github.com/desktop-app/legal/blob/master/LEGAL
//
#pragma once

#include "ton/ton_result.h"
#include "ton/ton_state.h"
#include "base/weak_ptr.h"

namespace Ton {

class Wallet;
struct WalletViewerState;
struct LoadedSlice;

class AccountViewer final : public base::has_weak_ptr {
 public:
  AccountViewer(not_null<Wallet *> wallet, QByteArray publicKey, QString address,
                rpl::producer<WalletViewerState> state);

  [[nodiscard]] rpl::producer<WalletViewerState> state() const;

  void refreshNow(Callback<>);
  [[nodiscard]] rpl::producer<Callback<>> refreshNowRequests() const;
  void setRefreshEach(crl::time delay);
  [[nodiscard]] crl::time refreshEach() const;
  [[nodiscard]] rpl::producer<crl::time> refreshEachValue() const;

  void preloadSlice(const TransactionId &lastId);
  void preloadTokenSlice(const Symbol &symbol, const QString &tokenWalletAddress, const TransactionId &lastId);

  [[nodiscard]] rpl::producer<Result<std::pair<Symbol, LoadedSlice>>> loaded() const;
  [[nodiscard]] rpl::producer<not_null<const QString *>> tokenWalletDeployed() const;
  [[nodiscard]] rpl::producer<not_null<const QString *>> dePoolAdded() const;

 private:
  const not_null<Wallet *> _wallet;
  const QByteArray _publicKey;
  const QString _address;

  base::flat_set<TransactionId> _preloadIds;
  base::flat_set<QString> _knownDePools;

  rpl::producer<WalletViewerState> _state;
  rpl::variable<crl::time> _refreshEach;
  rpl::event_stream<Callback<>> _refreshNowRequests;
  rpl::event_stream<Result<std::pair<Symbol, LoadedSlice>>> _loadedResults;
  rpl::event_stream<not_null<const QString *>> _tokenWalletDeployed;
  rpl::event_stream<not_null<const QString *>> _dePoolAdded;
};

}  // namespace Ton
