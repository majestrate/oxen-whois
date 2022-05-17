#include <future>
#include <getopt.h>
#include <nlohmann/json.hpp>
#include <oxenmq/base32z.h>
#include <oxenmq/base64.h>
#include <oxenmq/hex.h>
#include <oxenmq/oxenmq.h>
#include <sodium/crypto_aead_xchacha20poly1305.h>
#include <sodium/crypto_generichash.h>
#include <uvw.hpp>

// lns type enum for determining what kind of lsn entry we are looking at
enum LNSType { eTypeUnknown = -1, eTypeSession = 0, eTypeLokinet = 2 };

struct MQ {
  MQ(oxenmq::address remote, bool verbose)
      : mq{[](oxenmq::LogLevel level, const char *file, int line,
              std::string msg) {
          std::cout << level << " " << file << ":" << line << msg << std::endl;
        }} {
    if (verbose)
      mq.log_level(oxenmq::LogLevel::debug);
    mq.start();
    conn = mq.connect_remote(remote, nullptr, nullptr);
  }
  oxenmq::OxenMQ mq;
  oxenmq::ConnectionID conn;

  template <typename... Args>
  void request(std::string method, const Args &...args) {
    mq.request(conn, std::move(method), args...);
  }
};

std::optional<std::vector<uint8_t>> decrypt_value(std::string encrypted,
                                                     std::string nouncehex,
                                                     std::string name,
                                                     LNSType type) {

  const auto ciphertext = oxenmq::from_hex(encrypted);
  const auto nounce = oxenmq::from_hex(nouncehex);

  const auto payloadsize =
      ciphertext.size() - crypto_aead_xchacha20poly1305_ietf_ABYTES;

  size_t expected_size = type == LNSType::eTypeLokinet ? 32 :
      type == LNSType::eTypeSession ? 33 :
      0 /* who knows */;

  if (not expected_size or payloadsize != expected_size)
    return {};

  std::array<uint8_t, 32> derivedKey{};
  std::array<uint8_t, 32> namehash{};
  crypto_generichash(namehash.data(), namehash.size(),
                     reinterpret_cast<const unsigned char *>(name.data()),
                     name.size(), nullptr, 0);
  crypto_generichash(derivedKey.data(), derivedKey.size(),
                     reinterpret_cast<const unsigned char *>(name.data()),
                     name.size(), namehash.data(), namehash.size());
  std::vector<uint8_t> result(payloadsize);
  if (crypto_aead_xchacha20poly1305_ietf_decrypt(
          result.data(), nullptr, nullptr,
          reinterpret_cast<const unsigned char *>(ciphertext.data()),
          ciphertext.size(), nullptr, 0,
          reinterpret_cast<const unsigned char *>(nounce.data()),
          derivedKey.data()) == -1) {
    return {};
  }
  return result;
}

class WhoisServer : public std::enable_shared_from_this<WhoisServer> {
  std::shared_ptr<uvw::Loop> m_Loop;
  std::shared_ptr<uvw::TCPHandle> m_Server;
  std::shared_ptr<MQ> m_MQ;

  const std::pair<std::string, std::string> m_Bind;

  template <typename ResultHandler>
  void AsyncGetAddress(std::string namehash, std::string name, LNSType type,
                       ResultHandler handler) {
    if (type == eTypeUnknown) {
      handler(std::nullopt);
      return;
    }
    const nlohmann::json req{{"type", type}, {"name_hash", namehash}};
    m_MQ->request(
        "rpc.lns_resolve",
        [handler, name, type](bool success, std::vector<std::string> data) {
          if (not success) {
            handler(std::nullopt);
          } else {
            try {
              const auto j = nlohmann::json::parse(data[1]);
              const auto itr = j.find("nonce");
              if (itr == j.end()) {
                handler(std::nullopt);
              } else {
                const auto value_itr = j.find("encrypted_value");
                if (value_itr == j.end()) {
                  handler(std::nullopt);
                } else
                  handler(decrypt_value(value_itr->get<std::string>(),
                                        itr->get<std::string>(), name, type));
              }
            } catch (...) {
              handler(std::nullopt);
            }
          }
        },
        req.dump());
  }

  std::optional<std::vector<uint8_t>>
  GetAddress(std::string namehash, std::string name, LNSType type) {
    std::promise<std::optional<std::vector<uint8_t>>> promise;
    AsyncGetAddress(namehash, name, type,
                    [&promise](auto result) { promise.set_value(result); });
    auto ftr = promise.get_future();
    return ftr.get();
  }

  void setupConnection(std::shared_ptr<uvw::TCPHandle> conn) {
    conn->on<uvw::DataEvent>(
        [self = shared_from_this()](const uvw::DataEvent &event,
                                    uvw::TCPHandle &conn) {
          self->HandleConnRead(conn, event.data.get(), event.length);
        });
    conn->data(shared_from_this());
  }

  void HandleConnRead(uvw::TCPHandle &conn, const char *ptr, size_t len) {
    if (len <= 2) {
      // short read
      conn.close();
      return;
    }
    std::array<unsigned char, 32> namehash{};
    const std::string name{ptr, len - 2};
    std::cout << "lookup name : " << name << std::endl;
    crypto_generichash(namehash.data(), namehash.size(),
                       reinterpret_cast<const unsigned char *>(name.data()),
                       name.size(), nullptr, 0);

    const nlohmann::json params{
        {"types",
         {
             2,
             0,
         }},
        {"name_hash", oxenmq::to_base64(namehash.begin(), namehash.end())}};
    const nlohmann::json req{{"entries",
                              {
                                  params,
                              }}};
    m_MQ->request(
        "rpc.lns_names_to_owners",
        [conn = conn.shared_from_this(), self = shared_from_this(), name,
         namehash](bool success, std::vector<std::string> data) {
          std::stringstream writeBuf;
          auto SendReply = [&writeBuf, conn]() {
            auto str = writeBuf.str();
            std::vector<char> buf;
            buf.resize(str.size());
            std::copy_n(str.c_str(), buf.size(), buf.data());
            conn->write(buf.data(), buf.size());
            conn->close();
          };
          if ((not success) or data.size() < 2) {
            writeBuf << "; cannot find info on " << name;
            SendReply();
            return;
          }
          try {
            size_t n = 0;
            const auto j = nlohmann::json::parse(data[1]);

            if (j.find("entries") == j.end()) {
              writeBuf << "; no results for " << name;
              SendReply();
              return;
            }
            constexpr auto permit_key = [](std::string k) {
              return k != "encrypted_value" and k != "entry_index";
            };
            for (const auto &item : j["entries"]) {
              std::string encrypted;
              LNSType type = eTypeUnknown;
              writeBuf << "; entry " << n++ << " for " << name << std::endl;
              for (const auto &[key, value] : item.items()) {
                if (key == "type") {
                  if (not value.is_number()) {
                    continue;
                  }
                  switch (value.get<int>()) {
                  case eTypeSession:
                    type = eTypeSession;
                    writeBuf << "type: session" << std::endl;
                    break;
                  case eTypeLokinet:
                    type = eTypeLokinet;
                    writeBuf << "type: lokinet" << std::endl;
                    break;
                  default:
                    writeBuf << "type: " << value << std::endl;
                    break;
                  }
                } else if (permit_key(key)) {
                  writeBuf << key << ": ";
                  if (value.is_string())
                    writeBuf << value.get<std::string_view>();
                  else
                    writeBuf << value;
                  writeBuf << std::endl;
                } else if (key == "encrypted_value") {
                  encrypted = value.get<std::string>();
                }
              }

              if (auto maybe = self->GetAddress(
                      oxenmq::to_hex(namehash.begin(), namehash.end()), name,
                      type)) {

                switch (type) {
                case eTypeSession:
                  writeBuf << "session-id: "
                           << oxenmq::to_hex(maybe->begin(), maybe->end())
                           << std::endl;
                  break;
                case eTypeLokinet:
                  writeBuf << "address: "
                           << oxenmq::to_base32z(maybe->begin(), maybe->end())
                           << ".loki" << std::endl;
                  break;
                default:
                  writeBuf << "plaintext value: "
                           << oxenmq::to_base64(maybe->begin(), maybe->end())
                           << std::endl;
                  break;
                }
              } else if (not encrypted.empty()) {
                writeBuf << "encrypted-value: " << encrypted << std::endl;
              }
              writeBuf << std::endl;
            }
          } catch (std::exception &ex) {
            writeBuf << "; exception thrown while parsing response: ";
            writeBuf << ex.what();
          }
          SendReply();
        },
        req.dump());
  }

public:
  WhoisServer(oxenmq::address rpc, std::pair<std::string, std::string> bindAddr,
              bool verbose)
      : m_Loop{uvw::Loop::getDefault()},
        m_MQ{std::make_shared<MQ>(rpc, verbose)}, m_Bind{bindAddr} {}

  void MainLoop() {
    addrinfo hints = {0, AF_INET, SOCK_STREAM, 0, 0, 0, 0};
    auto lookup = m_Loop->resource<uvw::GetAddrInfoReq>();
    std::cout << "looking up " << m_Bind.first << "... " << std::endl;
    auto [success, result] =
        lookup->addrInfoSync(m_Bind.first, m_Bind.second, &hints);
    if (not success) {
      std::cerr << "cannot lookup " << m_Bind.first << std::endl;
      return;
    }

    addrinfo *next = result.get();

    const sockaddr *addr = nullptr;

    do {
      if (next->ai_family == AF_INET)
        addr = ((const sockaddr *)next->ai_addr);
      next = next->ai_next;
    } while (next);
    if (addr == nullptr) {
      std::cerr << "no such address " << m_Bind.first << std::endl;
      return;
    }

    m_Server = m_Loop->resource<uvw::TCPHandle>();
    m_Server->on<uvw::ListenEvent>(
        [self = shared_from_this()](auto, uvw::TCPHandle &serv) {
          auto client = serv.loop().resource<uvw::TCPHandle>();
          self->setupConnection(client);
          serv.accept(*client);
          client->read();
        });
    m_Server->on<uvw::ErrorEvent>(
        [self = shared_from_this()](const uvw::ErrorEvent &ev,
                                    uvw::TCPHandle &serv) {
          std::cerr << "failed: " << ev.what() << std::endl;
          serv.close();
          ::exit(1);
        });
    std::cout << "bind to " << m_Bind.first << " on " << m_Bind.second
              << std::endl;
    m_Server->bind(*addr);
    m_Server->listen();
    m_Loop->run();
  }
};

int printhelp(std::string exe) {
  std::cout << "usage: " << exe
            << " -[h|v] [-r rpcurl | -P bindport | -H bindhost]" << std::endl;
  return 0;
}

int main(int argc, char *argv[]) {

  oxenmq::address rpc{"ipc:///var/lib/oxen/oxend.sock"};
  bool verbose = false;
  std::string bindport = "whois";
  std::string bindhost = "0.0.0.0";
  int opt;
  while ((opt = ::getopt(argc, argv, "hvr:P:H:")) != -1) {
    switch (opt) {
    case 'h':
      return printhelp(argv[0]);
    case 'v':
      verbose = true;
      break;
    case 'r':
      rpc = oxenmq::address{optarg};
      break;
    case 'p':
      bindport = optarg;
      break;
    case 'H':
      bindhost = optarg;
      break;
    }
  }

  auto serv = std::make_shared<WhoisServer>(
      rpc, std::pair<std::string, std::string>{bindhost, bindport}, verbose);
  signal(SIGINT, [](auto) { exit(0); });
  signal(SIGTERM, [](auto) { exit(0); });
  serv->MainLoop();
  return 0;
}
