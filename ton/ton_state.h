// This file is part of Desktop App Toolkit,
// a set of libraries for developing nice desktop applications.
//
// For license and copyright information please follow this link:
// https://github.com/desktop-app/legal/blob/master/LEGAL
//
#pragma once

namespace Ton {

struct TransactionId {
	int64 id = 0;
	QByteArray hash;
};

struct AccountState {
	int64 balance = 0;
	int64 syncTime = 0;
	TransactionId lastTransactionId;
	QByteArray frozenHash;
	int32 seqNo = 0;
};

struct Message {
	QString source;
	QString destination;
	int64 value = 0;
	int64 forwardFee = 0;
	int64 immediateHypercubeRoutingFee = 0;
	int64 created = 0;
	QByteArray bodyHash;
	QByteArray message;
};

struct Transaction {
	TransactionId id;
	int64 time = 0;
	QByteArray data;
	int64 fee = 0;
	int64 storageFee = 0;
	int64 otherFee = 0;
	Message incoming;
	std::vector<Message> outgoing;
};

struct TransactionsSlice {
	std::vector<Transaction> list;
	TransactionId previousId;
};

} // namespace Ton