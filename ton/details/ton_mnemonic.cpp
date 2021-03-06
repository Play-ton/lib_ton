#include "ton_mnemonic.h"

#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>

#include "ton/ton_result.h"
#include "base/openssl_help.h"

namespace Ton::details {
constexpr auto kInvalidDerivationPath = "Invalid derivation path";

constexpr uint32_t SECP256K1_N_0 = 0xD0364141u;
constexpr uint32_t SECP256K1_N_1 = 0xBFD25E8Cu;
constexpr uint32_t SECP256K1_N_2 = 0xAF48A03Bu;
constexpr uint32_t SECP256K1_N_3 = 0xBAAEDCE6u;
constexpr uint32_t SECP256K1_N_4 = 0xFFFFFFFEu;
constexpr uint32_t SECP256K1_N_5 = 0xFFFFFFFFu;
constexpr uint32_t SECP256K1_N_6 = 0xFFFFFFFFu;
constexpr uint32_t SECP256K1_N_7 = 0xFFFFFFFFu;

constexpr uint32_t SECP256K1_N_C_0 = ~SECP256K1_N_0 + 1u;
constexpr uint32_t SECP256K1_N_C_1 = ~SECP256K1_N_1;
constexpr uint32_t SECP256K1_N_C_2 = ~SECP256K1_N_2;
constexpr uint32_t SECP256K1_N_C_3 = ~SECP256K1_N_3;
constexpr uint32_t SECP256K1_N_C_4 = 1u;

constexpr uint32_t HARDENED_BIT = 1u << 31u;
constexpr int PBKDF2_ROUNDS = 2048;

constexpr auto ENTROPY_OFFSET = 8u;

struct CurveSecp256k1 {
  CurveSecp256k1() noexcept {
    group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    Expects(group != nullptr);
  }
  ~CurveSecp256k1() {
    EC_GROUP_free(group);
  }

  CurveSecp256k1(CurveSecp256k1 const&) = delete;
  void operator=(CurveSecp256k1 const& x) = delete;

  EC_GROUP* group{};
};

static CurveSecp256k1 secp256k1{};

struct BigNumber {
  explicit BigNumber(bytes::const_span buf) noexcept {
    handle = BN_bin2bn(reinterpret_cast<const uint8_t*>(buf.data()), buf.size(), nullptr);
    Expects(handle != nullptr);
  }
  ~BigNumber() {
    BN_free(handle);
  }

  BigNumber(BigNumber const&) = delete;
  void operator=(BigNumber const& x) = delete;

  BigNumber(BigNumber&& other) noexcept = default;

  BIGNUM* handle{};
};

struct PrivateKey {
  explicit PrivateKey(bytes::const_span buf) noexcept {
    handle = EC_KEY_new();
    Expects(handle != nullptr);
    Expects(EC_KEY_set_group(handle, secp256k1.group));

    BigNumber num{buf};
    Expects(EC_KEY_set_private_key(handle, num.handle));
  }
  ~PrivateKey() {
    EC_KEY_free(handle);
  }

  PrivateKey(PrivateKey const&) = delete;
  void operator=(PrivateKey const& x) = delete;

  PrivateKey(PrivateKey&& other) noexcept = default;

  auto reset(const BigNumber& num) -> Result<> {
    EC_KEY_free(handle);

    handle = EC_KEY_new();
    Expects(handle != nullptr);
    Expects(EC_KEY_set_group(handle, secp256k1.group));
    Expects(EC_KEY_set_private_key(handle, num.handle));

    return finalize();
  }

  [[nodiscard]] auto finalize() const -> Result<> {
    auto private_key = EC_KEY_get0_private_key(handle);
    auto pub_key = EC_POINT_new(secp256k1.group);
    if (!EC_POINT_mul(secp256k1.group, pub_key, private_key, nullptr, nullptr, nullptr)) {
      EC_POINT_free(pub_key);
      return Error{Error::Type::TonLib, "failed to create secp256k1 public key"};
    }

    Expects(EC_KEY_set_public_key(handle, pub_key));
    EC_POINT_free(pub_key);

    if (!EC_KEY_check_key(handle)) {
      return Error{Error::Type::TonLib, "invalid secp256k1 private key"};
    }

    return Result<>{};
  }

  [[nodiscard]] auto createED25519PrivateKey() const -> Result<QByteArray> {
    QByteArray bytes(32, 0);

    const auto len = EC_KEY_priv2oct(handle, reinterpret_cast<uint8_t*>(bytes.data()), bytes.size());
    if (len != bytes.size()) {
      return Error{Error::Type::TonLib, "failed to export to ed25519 private key"};
    }

    return Result<QByteArray>{std::move(bytes)};
  }

  [[nodiscard]] auto serialize(bytes::span bytes) const -> Result<> {
    if (BN_bn2binpad(data(), reinterpret_cast<uint8_t*>(bytes.data()), bytes.size())) {
      return Result<>{};
    } else {
      return Error{Error::Type::TonLib, "failed to serialize private key"};
    }
  }

  [[nodiscard]] auto serializeCompressedPublic(bytes::span bytes) const -> Result<> {
    auto point = EC_KEY_get0_public_key(handle);
    if (point == nullptr) {
      return Error{Error::Type::TonLib, "failed to get secp256k1 public key"};
    }

    uint8_t* buffer{};
    auto len = EC_POINT_point2buf(secp256k1.group, point, POINT_CONVERSION_COMPRESSED, &buffer, nullptr);
    if (len != bytes.size()) {
      if (buffer != nullptr) {
        OPENSSL_free(buffer);
      }
      return Error{Error::Type::TonLib, "failed to convert secp256k1 public key"};
    }
    std::memcpy(bytes.data(), buffer, len);
    OPENSSL_free(buffer);
    return Result<>{};
  }

  [[nodiscard]] auto data() const -> const BIGNUM* {
    return EC_KEY_get0_private_key(handle);
  }

  EC_KEY* handle{};
};

struct Scalar {
  static auto fromBigNum(const BIGNUM* num) -> Result<Scalar> {
    bytes::vector bytes(32);
    if (BN_bn2binpad(num, reinterpret_cast<uint8_t*>(bytes.data()), 32) != 32) {
      return Error{Error::Type::TonLib, "failed to construct secp256k1 scalar"};
    }
    Scalar result{};
    result.setBuffer(bytes);
    return result;
  }

  [[nodiscard]] auto createBigNum() const -> BigNumber {
    return BigNumber{getBuffer()};
  }

  auto setBuffer(bytes::const_span buf) -> bool {
    for (auto i = 0; i < 8; ++i) {
      v[7 - i] = static_cast<uint32_t>(buf[i * 4 + 3])             //
                 | (static_cast<uint32_t>(buf[i * 4 + 2]) << 8u)   //
                 | (static_cast<uint32_t>(buf[i * 4 + 1]) << 16u)  //
                 | (static_cast<uint32_t>(buf[i * 4 + 0]) << 24u);
    }

    return reduce(checkOverflow());
  }

  [[nodiscard]] auto getBuffer() const -> bytes::vector {
    bytes::vector buf(32);

    for (auto i = 0; i < 8; ++i) {
      buf[i * 4 + 0] = static_cast<std::byte>(v[7 - i] >> 24u);
      buf[i * 4 + 1] = static_cast<std::byte>(v[7 - i] >> 16u);
      buf[i * 4 + 2] = static_cast<std::byte>(v[7 - i] >> 8u);
      buf[i * 4 + 3] = static_cast<std::byte>(v[7 - i]);
    }

    return buf;
  }

  auto checkOverflow() -> bool {
    auto yes = false;
    auto no = false;
    no = no || (v[7] < SECP256K1_N_7); /* No need for a > check. */
    no = no || (v[6] < SECP256K1_N_6); /* No need for a > check. */
    no = no || (v[5] < SECP256K1_N_5); /* No need for a > check. */
    no = no || (v[4] < SECP256K1_N_4);
    yes = yes || ((v[4] > SECP256K1_N_4) && !no);
    no = no || ((v[3] < SECP256K1_N_3) && !yes);
    yes = yes || ((v[3] > SECP256K1_N_3) && !no);
    no = no || ((v[2] < SECP256K1_N_2) && !yes);
    yes = yes || ((v[2] > SECP256K1_N_2) && !no);
    no = no || ((v[1] < SECP256K1_N_1) && !yes);
    yes = yes || ((v[1] > SECP256K1_N_1) && !no);
    yes = yes || ((v[0] >= SECP256K1_N_0) && !no);
    return yes;
  }

  auto reduce(bool overflow) -> bool {
    uint64_t o = overflow;
    uint64_t t;
    t = static_cast<uint64_t>(v[0]) + o * static_cast<uint64_t>(SECP256K1_N_C_0);
    v[0] = static_cast<uint32_t>(t);
    t >>= 32u;
    t += static_cast<uint64_t>(v[1]) + o * static_cast<uint64_t>(SECP256K1_N_C_1);
    v[1] = static_cast<uint32_t>(t);
    t >>= 32u;
    t += static_cast<uint64_t>(v[2]) + o * static_cast<uint64_t>(SECP256K1_N_C_2);
    v[2] = static_cast<uint32_t>(t);
    t >>= 32u;
    t += static_cast<uint64_t>(v[3]) + o * static_cast<uint64_t>(SECP256K1_N_C_3);
    v[3] = static_cast<uint32_t>(t);
    t >>= 32u;
    t += static_cast<uint64_t>(v[4]) + o * static_cast<uint64_t>(SECP256K1_N_C_4);
    v[4] = static_cast<uint32_t>(t);
    t >>= 32u;
    t += static_cast<uint64_t>(v[5]);
    v[5] = static_cast<uint32_t>(t);
    t >>= 32u;
    t += static_cast<uint64_t>(v[6]);
    v[6] = static_cast<uint32_t>(t);
    t >>= 32u;
    t += static_cast<uint64_t>(v[7]);
    v[7] = static_cast<uint32_t>(t);
    return overflow;
  }

  auto addInPlace(const Scalar& a, const Scalar& b) -> bool {
    uint64_t t = 0;
    for (auto i = 0; i < 8; ++i) {
      t += static_cast<uint64_t>(a.v[i]) + static_cast<uint64_t>(b.v[i]);
      v[i] = static_cast<uint32_t>(t);
      t >>= 32u;
    }

    auto overflow = t + static_cast<uint64_t>(checkOverflow());
    Expects(overflow == 0 || overflow == 1);
    overflow = overflow | static_cast<uint64_t>(reduce(overflow == 1));
    return overflow == 1;
  }

  std::array<uint32_t, 8> v{};
};

struct ExtendedPrivateKey {
  auto derive(uint32_t number) -> Result<> {
    bytes::vector hmacInput(37);

    if ((number & HARDENED_BIT) == 0) {
      if (const auto r = secretKey.serializeCompressedPublic(bytes::span(hmacInput.data(), 33)); !r.has_value()) {
        return r.error();
      }
    } else {
      hmacInput[0] = static_cast<std::byte>(0);
      if (const auto r = secretKey.serialize(bytes::span(hmacInput.data() + 1, 32)); !r.has_value()) {
        return r.error();
      }
    }

    for (uint32_t i = 0; i < 4; ++i) {
      const uint8_t shift = static_cast<uint8_t>(3u - i) << 3u;
      hmacInput[33 + i] = static_cast<std::byte>(number >> shift);
    }

    const auto hmac = openssl::HmacSha512(chainCode, hmacInput);

    PrivateKey tempKey{bytes::const_span(hmac.data(), 32)};
    if (const auto r = tempKey.finalize(); !r.has_value()) {
      return r.error();
    }

    auto sourceData = Scalar::fromBigNum(tempKey.data());
    if (!sourceData.has_value()) {
      return sourceData.error();
    }

    auto currentData = Scalar::fromBigNum(secretKey.data());
    if (!currentData.has_value()) {
      return currentData.error();
    }

    Scalar result{};
    result.addInPlace(*sourceData, *currentData);
    secretKey.reset(result.createBigNum());

    chainCode.resize(32);
    std::memcpy(chainCode.data(), hmac.data() + 32, 32);

    return Result<>{};
  }

  PrivateKey secretKey;
  bytes::vector chainCode;
};

auto ChildNumberFromString(const QString& str) -> Result<uint32_t> {
  auto ok = true;
  uint32_t value;
  if (str.size() > 1 && str[str.size() - 1] == '\'') {
    str.left(str.size() - 1).toInt();
    if (!ok) {
      return Error{Error::Type::TonLib, kInvalidDerivationPath};
    }
    value |= HARDENED_BIT;
  } else {
    value = str.toInt(&ok);
    if (!ok) {
      return Error{Error::Type::TonLib, kInvalidDerivationPath};
    }
  }
  return value;
}

auto DerivationPathFromString(const QString& str) -> Result<std::vector<uint32_t>> {
  auto path = str.split('/');

  if (path.empty() || path[0] != "m") {
    return Error{Error::Type::TonLib, kInvalidDerivationPath};
  }

  std::vector<uint32_t> result;
  result.reserve(path.size() - 1);
  for (const auto& item : path) {
    if (item == "m") {
      continue;
    }

    auto value = ChildNumberFromString(item);
    if (!value.has_value()) {
      return value.error();
    }

    result.emplace_back(std::move(*value));
  }
  return result;
}

auto RecoverKey(const QString& mnemonic) -> Result<QByteArray> {
  const auto rawMnemonic = mnemonic.toStdString();
  constexpr std::string_view salt = "mnemonic";
  const auto seed = openssl::Pbkdf2Sha512(
      bytes::const_span(reinterpret_cast<const std::byte*>(rawMnemonic.data()), rawMnemonic.size()),  //
      bytes::const_span(reinterpret_cast<const std::byte*>(salt.data()), salt.size()),                //
      PBKDF2_ROUNDS);

  constexpr std::string_view hmacKey = "Bitcoin seed";
  const auto hmac =
      openssl::HmacSha512(bytes::const_span(reinterpret_cast<const std::byte*>(hmacKey.data()), hmacKey.size()),  //
                          seed);

  ExtendedPrivateKey sk{
      .secretKey = PrivateKey{bytes::const_span(hmac.data(), hmac.size())},
      .chainCode = bytes::vector(hmac.begin() + 32, hmac.end()),
  };
  if (const auto r = sk.secretKey.finalize(); !r.has_value()) {
    return r.error();
  }

  const auto derivationPath = DerivationPathFromString("m/44'/396'/0'/0/0");
  if (!derivationPath.has_value()) {
    return derivationPath.error();
  }

  for (auto path : *derivationPath) {
    if (const auto r = sk.derive(path); !r.has_value()) {
      return r.error();
    }
  }

  return sk.secretKey.createED25519PrivateKey();
}

enum MnemonicType : uint32_t {
  Words12 = (128u << ENTROPY_OFFSET) | 4u,
  Words24 = (256u << ENTROPY_OFFSET) | 8u,
};

constexpr auto defaultMnemonic = MnemonicType::Words12;

auto EntropyBits(MnemonicType type) -> size_t {
  return type >> ENTROPY_OFFSET;
}

auto ChecksumBits(MnemonicType type) -> size_t {
  return type & 0xffu;
}

auto TotalBits(MnemonicType type) -> size_t {
  return EntropyBits(type) + ChecksumBits(type);
}

auto WordCount(MnemonicType type) -> size_t {
  return TotalBits(type) / 11u;
}

template <typename T>
inline constexpr auto MakeOnes(uint8_t count) -> T {
  return static_cast<T>((T{0b1u} << count) - T{0b1u});
}

std::vector<QString> GenerateBIP39Phrase(const std::vector<QString>& dictionary) {
  const auto entropySize = EntropyBits(defaultMnemonic) >> 3u;
  const auto resultLen = WordCount(defaultMnemonic);

  bytes::vector buffer(entropySize + 1);
  openssl::FillRandomValues(bytes::span(buffer.data(), entropySize));

  auto checksum_byte = openssl::Sha256(bytes::const_span(buffer.data(), entropySize))[0];
  buffer[entropySize] = checksum_byte;

  std::vector<QString> result;
  result.reserve(resultLen);

  const auto* slice = buffer.data();

  size_t offset = 0;
  for (int i = 0; i < resultLen; i++) {
    const auto j = offset / 8u;

    const auto first_byte_length = static_cast<uint16_t>(8u - (offset & 0b111u));

    const auto second_byte_length = std::min(11u - first_byte_length, 8u);
    const auto second_byte_offset = static_cast<uint16_t>(8u - second_byte_length);

    const auto third_byte_length = 11u - first_byte_length - second_byte_length;
    const auto third_byte_offset = static_cast<uint16_t>(8u - third_byte_length);

    uint16_t word_i{};
    word_i |= static_cast<uint16_t>(slice[j]) & MakeOnes<uint16_t>(first_byte_length);
    word_i <<= second_byte_length;
    word_i |= static_cast<uint16_t>(slice[j + 1]) >> second_byte_offset;
    if (third_byte_length > 0) {
      word_i <<= third_byte_length;
      word_i |= static_cast<uint16_t>(slice[j + 2]) >> third_byte_offset;
    }

    offset += 11u;

    result.emplace_back(dictionary[word_i]);
  }

  return result;
}

}  // namespace Ton::details
