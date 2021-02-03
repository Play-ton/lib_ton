// This file is part of Desktop App Toolkit,
// a set of libraries for developing nice desktop applications.
//
// For license and copyright information please follow this link:
// https://github.com/desktop-app/legal/blob/master/LEGAL
//
#include "ton/details/ton_account_viewers.h"

#include "ton/ton_result.h"
#include "ton/ton_wallet.h"
#include "ton/ton_account_viewer.h"
#include "ton/details/ton_storage.h"
#include "ton/details/ton_parse_state.h"
#include "storage/cache/storage_cache_database.h"

#include <iostream>
#include <shared_mutex>

namespace Ton::details {
namespace {

constexpr auto kRefreshWithPendingTimeout = 6 * crl::time(1000);

std::vector<PendingTransaction> ComputePendingTransactions(std::vector<PendingTransaction> list,
                                                           const AccountState &state, const TransactionsSlice &last) {
  const auto processed = [&](const PendingTransaction &transaction) {
    return (transaction.sentUntilSyncTime < state.syncTime) ||
           (ranges::find(last.list, transaction.fake) != end(last.list));
  };
  list.erase(ranges::remove_if(list, processed), end(list));
  return list;
}

}  // namespace

AccountViewers::AccountViewers(not_null<Wallet *> owner, not_null<RequestSender *> lib,
                               not_null<Storage::Cache::Database *> db)
    : _owner(owner), _lib(lib), _db(db), _refreshTimer([=] { checkNextRefresh(); }) {
}

AccountViewers::~AccountViewers() {
  for (const auto &[address, viewers] : _map) {
    Assert(viewers.list.empty());
  }
}

rpl::producer<BlockchainTime> AccountViewers::blockchainTime() const {
  return _blockchainTime.events();
}

AccountViewers::Viewers *AccountViewers::findRefreshingViewers(const QString &address) {
  const auto i = _map.find(address);
  Assert(i != end(_map));
  if (i->second.list.empty()) {
    _map.erase(i);
    return nullptr;
  }
  return &i->second;
}

void AccountViewers::finishRefreshing(Viewers &viewers, Result<> result) {
  viewers.lastRefreshFinished = crl::now();
  if (result) {
    viewers.lastGoodRefresh = crl::now();
  }
  viewers.refreshing = false;
  InvokeCallback(base::take(viewers.refreshed), result);
}

template <typename Data>
bool AccountViewers::reportError(Viewers &viewers, Result<Data> result) {
  if (result.has_value()) {
    return false;
  }
  const auto weak = base::make_weak(this);
  finishRefreshing(viewers, result.error());
  if (!weak) {
    return true;
  }
  checkNextRefresh();
  return true;
}

void AccountViewers::saveNewState(Viewers &viewers, WalletState &&state, RefreshSource source) {
  const auto weak = base::make_weak(this);
  if (source != RefreshSource::Pending) {
    finishRefreshing(viewers);
  }
  if (!weak) {
    return;
  }
  if (viewers.state.current() != state) {
    if (source != RefreshSource::Database) {
      SaveWalletState(_db, state, nullptr);
    }
    viewers.state = std::move(state);
    if (!weak) {
      return;
    }
  }
  if (source == RefreshSource::Database) {
    refreshAccount(state.address, viewers);
  } else {
    checkNextRefresh();
  }
}

void AccountViewers::checkPendingForSameState(const QString &address, Viewers &viewers,
                                              const CurrencyMap<TokenStateValue> &tokenStates,
                                              const std::map<QString, DePoolParticipantState> &dePoolStates,
                                              const AccountState &state) {
  auto pending = ComputePendingTransactions(viewers.state.current().pendingTransactions, state, TransactionsSlice());
  auto currentState = viewers.state.current();
  if (tokenStates != currentState.tokenStates || dePoolStates != currentState.dePoolParticipantStates ||
      currentState.pendingTransactions != pending) {
    // Some pending transactions were discarded by the sync time.

    currentState.assetsList.erase(  //
        ranges::remove_if(          //
            currentState.assetsList,
            [&](const AssetListItem &item) {
              return v::match(
                  item,
                  [&](const AssetListItemToken &token) { return tokenStates.find(token.symbol) == end(tokenStates); },
                  [&](const AssetListItemDePool &dePool) {
                    return dePoolStates.find(dePool.address) == end(dePoolStates);
                  },
                  [](const auto &) { return false; });
            }),
        end(currentState.assetsList));

    saveNewState(  //
        viewers,
        WalletState{.address = address,
                    .account = state,
                    .lastTransactions = std::move(currentState.lastTransactions),
                    .pendingTransactions = std::move(pending),
                    .tokenStates = tokenStates,
                    .dePoolParticipantStates = dePoolStates,
                    .assetsList = std::move(currentState.assetsList)},
        RefreshSource::Remote);
  } else {
    finishRefreshing(viewers);
    checkNextRefresh();
  }
}

void AccountViewers::refreshAccount(const QString &address, Viewers &viewers) {
  const auto requested = crl::now();
  viewers.refreshing = true;

  using StateWithViewer = std::pair<AccountState, AccountViewers::Viewers *>;
  using TokensMap = std::map<Symbol, TokenStateValue>;
  using ContextData = std::tuple<StateWithViewer, TokensMap, DePoolStatesMap>;

  struct StateContext {
    using Done = Callback<ContextData>;

    explicit StateContext(const Done &done) : done{done} {
    }

    void setAccount(AccountState &&state, AccountViewers::Viewers *viewers) {
      std::unique_lock lock{mutex};
      account = std::make_pair(std::forward<AccountState>(state), viewers);
      checkComplete();
    }

    void setTokenStates(TokensMap &&value) {
      std::unique_lock lock{mutex};
      tokenStates = std::forward<TokensMap>(value);
      checkComplete();
    }

    void setDePoolParticipantStates(DePoolStatesMap &&value) {
      std::unique_lock lock{mutex};
      dePoolParticipantStates = std::forward<DePoolStatesMap>(value);
      checkComplete();
    }

    void checkComplete() const {
      if (account.has_value() && tokenStates.has_value() && dePoolParticipantStates.has_value()) {
        InvokeCallback(done, std::forward_as_tuple(std::move(*account), std::move(*tokenStates),
                                                   std::move(*dePoolParticipantStates)));
      }
    }

    std::optional<StateWithViewer> account;
    std::optional<TokensMap> tokenStates;
    std::optional<DePoolStatesMap> dePoolParticipantStates;

    Done done;
    std::shared_mutex mutex;
  };

  std::shared_ptr<StateContext> ctx{new StateContext{[=](Result<ContextData> result) {
    const auto [state, tokenStates, dePoolParticipantStates] = std::move(result.value());
    const auto [account, viewers] = std::move(state);

    auto currentState = viewers->state.current();
    if (account == currentState.account) {
      checkPendingForSameState(address, *viewers, tokenStates, dePoolParticipantStates, account);
      return;
    }

    const auto lastTransactionId = account.lastTransactionId;

    const auto received = [this, address, account = std::move(account), tokenStates = std::move(tokenStates),
                           dePoolParticipantStates = std::move(dePoolParticipantStates),
                           currentState = std::move(currentState)](Result<TransactionsSlice> result) mutable {
      const auto viewers = findRefreshingViewers(address);
      if (viewers == nullptr || reportError(*viewers, result)) {
        return;
      }

      currentState.assetsList.erase(  //
          ranges::remove_if(currentState.assetsList,
                            [&](const AssetListItem &item) {
                              return v::match(
                                  item,
                                  [&](const AssetListItemToken &token) {
                                    return tokenStates.find(token.symbol) == end(tokenStates);
                                  },
                                  [&](const AssetListItemDePool &dePool) {
                                    return dePoolParticipantStates.find(dePool.address) == end(dePoolParticipantStates);
                                  },
                                  [](const auto &) { return false; });
                            }),
          end(currentState.assetsList));

      saveNewStateEncrypted(address, *viewers,
                            WalletState{.address = address,
                                        .account = account,
                                        .lastTransactions = std::move(*result),
                                        .tokenStates = std::move(tokenStates),
                                        .dePoolParticipantStates = std::move(dePoolParticipantStates),
                                        .assetsList = std::move(currentState.assetsList)},
                            RefreshSource::Remote);
    };
    _owner->requestTransactions(address, lastTransactionId, received);
  }}};

  _owner->requestState(address, [=](Result<AccountState> result) {
    const auto viewers = findRefreshingViewers(address);
    if (!viewers || reportError(*viewers, result)) {
      return;
    }
    auto account = std::move(result.value());
    if (LocalTimeSyncer::IsRequestFastEnough(requested, crl::now())) {
      _blockchainTime.fire({requested, TimeId(account.syncTime)});
    }

    ctx->setAccount(std::move(account), viewers);
  });

  _owner->requestTokenStates(  //
      viewers.state.current().tokenStates, [=](Result<CurrencyMap<TokenStateValue>> tokenStates) {
        if (tokenStates.has_value()) {
          ctx->setTokenStates(std::move(tokenStates.value()));
        } else {
          std::cout << tokenStates.error().details.toStdString() << std::endl;
          ctx->setTokenStates(CurrencyMap<TokenStateValue>{});
        }
      });

  _owner->requestDePoolParticipantInfo(  //
      viewers.publicKey, viewers.state.current().dePoolParticipantStates, [=](Result<DePoolStatesMap> dePoolStates) {
        if (dePoolStates.has_value()) {
          ctx->setDePoolParticipantStates(std::move(dePoolStates.value()));
        } else {
          std::cout << dePoolStates.error().details.toStdString() << std::endl;
          ctx->setDePoolParticipantStates(DePoolStatesMap{});
        }
      });
}

void AccountViewers::saveNewStateEncrypted(const QString &address, Viewers &viewers, WalletState &&full,
                                           RefreshSource source) {
  auto last = full.lastTransactions;
  auto finish = [=, full = std::move(full)](Viewers &viewers, TransactionsSlice &&last) mutable {
    auto pending = (source == RefreshSource::Database)
                       ? full.pendingTransactions
                       : ComputePendingTransactions(viewers.state.current().pendingTransactions, full.account, last);
    saveNewState(viewers,
                 WalletState{.address = address,
                             .account = std::move(full.account),
                             .lastTransactions = std::move(last),
                             .pendingTransactions = std::move(pending),
                             .tokenStates = std::move(full.tokenStates),
                             .dePoolParticipantStates = std::move(full.dePoolParticipantStates),
                             .assetsList = std::move(full.assetsList)},
                 source);
  };

  const auto done = [=, previousId = std::move(last.previousId),
                     finish = std::move(finish)](Result<std::vector<Transaction>> &&result) mutable {
    const auto viewers = findRefreshingViewers(address);
    if (!viewers || reportError(*viewers, result)) {
      return;
    }
    finish(*viewers, TransactionsSlice{std::move(*result), std::move(previousId)});
  };
  _owner->trySilentDecrypt(viewers.publicKey, std::move(last.list), done);
}

void AccountViewers::checkNextRefresh() {
  constexpr auto kNoRefresh = std::numeric_limits<crl::time>::max();
  auto minWait = kNoRefresh;
  const auto now = crl::now();
  for (auto &[address, viewers] : _map) {
    if (viewers.refreshing.current()) {
      continue;
    }
    Assert(viewers.lastRefreshFinished > 0);
    Assert(!viewers.list.empty());
    const auto min = (*ranges::min_element(viewers.list, ranges::less(), &AccountViewer::refreshEach))->refreshEach();
    const auto use =
        viewers.state.current().pendingTransactions.empty() ? min : std::min(min, kRefreshWithPendingTimeout);
    const auto next = viewers.nextRefresh = viewers.lastRefreshFinished + use;
    const auto in = next - now;
    if (in <= 0) {
      refreshAccount(address, viewers);
      continue;
    }
    if (minWait > in) {
      minWait = in;
    }
  }
  if (minWait != kNoRefresh) {
    _refreshTimer.callOnce(minWait);
  }
}

void AccountViewers::refreshFromDatabase(const QString &address, Viewers &viewers) {
  viewers.refreshing = true;
  auto loaded = [=](Result<WalletState> result) {
    const auto viewers = findRefreshingViewers(address);
    if (!viewers) {
      return;
    }
    saveNewStateEncrypted(address, *viewers,
                          result.value_or(WalletState{.address = address, .assetsList = {Ton::AssetListItemWallet{}}}),
                          RefreshSource::Database);
  };
  LoadWalletState(_db, address, crl::guard(this, loaded));
}

std::unique_ptr<AccountViewer> AccountViewers::createAccountViewer(const QByteArray &publicKey,
                                                                   const QString &address) {
  const auto i =
      _map.emplace(address,
                   Viewers{publicKey, WalletState{.address = address, .assetsList = {Ton::AssetListItemWallet{}}}})
          .first;

  auto &viewers = i->second;
  auto state = rpl::combine(viewers.state.value(), viewers.lastGoodRefresh.value(), viewers.refreshing.value()) |
               rpl::map([](WalletState &&state, crl::time last, bool refreshing) {
                 return WalletViewerState{std::move(state), last, refreshing};
               });
  auto result = std::make_unique<AccountViewer>(_owner, publicKey, address, std::move(state));
  const auto raw = result.get();
  viewers.list.push_back(raw);

  if (!viewers.nextRefresh) {
    viewers.nextRefresh = raw->refreshEach();
    refreshFromDatabase(address, viewers);
  }

  raw->refreshEachValue() |
      rpl::start_with_next_done(
          [=] {  //
            checkNextRefresh();
          },
          [=] {
            const auto i = _map.find(address);
            Assert(i != end(_map));
            i->second.list.erase(ranges::remove(i->second.list, raw, &not_null<AccountViewer *>::get),
                                 end(i->second.list));
            if (i->second.list.empty() && !i->second.refreshing.current()) {
              _map.erase(i);
            }
          },
          viewers.lifetime);

  raw->refreshNowRequests()  //
      | rpl::start_with_next(
            [=](Callback<> &&done) {
              const auto i = _map.find(address);
              Assert(i != end(_map));
              i->second.refreshed = std::move(done);
              if (!i->second.refreshing.current()) {
                refreshAccount(address, i->second);
              }
            },
            viewers.lifetime);

  return result;
}

void AccountViewers::addPendingTransaction(const PendingTransaction &pending) {
  const auto address = pending.fake.incoming.destination;
  const auto i = _map.find(address);
  if (i != end(_map)) {
    auto state = i->second.state.current();
    state.pendingTransactions.insert(begin(state.pendingTransactions), pending);
    saveNewState(i->second, std::move(state), RefreshSource::Pending);
  }
}

void AccountViewers::addDePool(const QString &account, const QString &dePoolAddress,
                               DePoolParticipantState &&participantState) {
  const auto i = _map.find(account);
  if (i != end(_map)) {
    auto state = i->second.state.current();
    state.dePoolParticipantStates.emplace(dePoolAddress, std::move(participantState));

    const auto it = ranges::find_if(state.assetsList, [&](const AssetListItem &item) {
      return v::match(
          item, [&](const AssetListItemDePool &token) { return token.address == dePoolAddress; },
          [](const auto &) { return false; });
    });
    if (it == end(state.assetsList)) {
      state.assetsList.emplace_back(AssetListItemDePool{.address = dePoolAddress});
    }

    saveNewState(i->second, std::move(state), RefreshSource::Remote);
  }
}

void AccountViewers::removeDePool(const QString &account, const QString &dePoolAddress) {
  const auto i = _map.find(account);
  if (i != end(_map)) {
    auto state = i->second.state.current();

    const auto it = state.dePoolParticipantStates.find(dePoolAddress);
    if (it != end(state.dePoolParticipantStates)) {
      const auto assetIt = ranges::find_if(state.assetsList, [&](const AssetListItem &item) {
        return v::match(
            item, [&](const AssetListItemDePool &token) { return it->first == token.address; },
            [](const auto &) { return false; });
      });
      if (assetIt != end(state.assetsList)) {
        state.assetsList.erase(assetIt);
      }
      state.dePoolParticipantStates.erase(it);
    }

    saveNewState(i->second, std::move(state), RefreshSource::Remote);
  }
}

void AccountViewers::addToken(const QString &account, TokenState &&tokenState) {
  const auto i = _map.find(account);
  if (i != end(_map)) {
    auto state = i->second.state.current();
    state.tokenStates.emplace(  //
        tokenState.token,       //
        TokenStateValue{
            .rootContractAddress = tokenState.rootContractAddress,
            .walletContractAddress = tokenState.walletContractAddress,
            .lastTransactions = tokenState.lastTransactions,
            .balance = tokenState.balance,
        });

    const auto it = ranges::find_if(state.assetsList, [&](const AssetListItem &item) {
      return v::match(
          item, [&](const AssetListItemToken &token) { return token.symbol == tokenState.token; },
          [](const auto &) { return false; });
    });
    if (it == end(state.assetsList)) {
      state.assetsList.emplace_back(AssetListItemToken{.symbol = tokenState.token});
    }

    saveNewState(i->second, std::move(state), RefreshSource::Remote);
  }
}

void AccountViewers::removeToken(const QString &account, const QString &walletContractAddress) {
  const auto i = _map.find(account);
  if (i != end(_map)) {
    auto state = i->second.state.current();

    const auto it = ranges::find_if(state.tokenStates, [&](const std::pair<Symbol, TokenStateValue> &item) {
      return item.second.walletContractAddress == walletContractAddress;
    });
    if (it != state.tokenStates.end()) {
      const auto assetIt = ranges::find_if(state.assetsList, [&](const AssetListItem &item) {
        return v::match(
            item, [&](const AssetListItemToken &token) { return it->first == token.symbol; },
            [](const auto &) { return false; });
      });
      if (assetIt != end(state.assetsList)) {
        state.assetsList.erase(assetIt);
      }
      state.tokenStates.erase(it);
    }

    saveNewState(i->second, std::move(state), RefreshSource::Remote);
  }
}

void AccountViewers::reorderAssets(const QString &account, int oldPosition, int newPosition) {
  const auto i = _map.find(account);
  if (i != end(_map)) {
    auto state = i->second.state.current();
    const auto assetCount = static_cast<int>(state.assetsList.size());
    base::reorder(state.assetsList, std::min(oldPosition, assetCount), std::min(newPosition, assetCount));
    saveNewState(i->second, std::move(state), RefreshSource::Remote);
  }
}

}  // namespace Ton::details
