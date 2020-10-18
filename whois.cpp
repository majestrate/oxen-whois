#include <uv.h>
#include <lokimq/lokimq.h>
#include <lokimq/base64.h>
#include <lokimq/base32z.h>
#include <lokimq/hex.h>
#include <sodium/crypto_generichash.h>
#include <sodium/crypto_aead_xchacha20poly1305.h>
#include <nlohmann/json.hpp>
#include <getopt.h>
#include <future>


// lns type enum for determining what kind of lsn entry we are looking at
enum LNSType
{
  eTypeUnknown = -1,
  eTypeSession = 0,
  eTypeLokinet = 2
};


struct LMQ
{
  explicit LMQ(std::string remote)
  {
    lmq.start();
    conn = lmq.connect_remote(remote, nullptr, nullptr);
  }

  
  lokimq::LokiMQ lmq;
  lokimq::ConnectionID conn;
};

std::optional<std::array<uint8_t, 32>>
decrypt_value(std::string encrypted, std::string nouncehex, std::string name, LNSType type)
{
  // TODO: implement
  if(type == eTypeSession)
    return std:: nullopt;
  const auto ciphertext = lokimq::from_hex(encrypted);
  const auto nounce = lokimq::from_hex(nouncehex);
  
  const auto payloadsize = ciphertext.size() - crypto_aead_xchacha20poly1305_ietf_ABYTES;
  if (payloadsize != 32)
    return {};
  
  std::array<uint8_t, 32> derivedKey{};
  std::array<uint8_t, 32> namehash{};
  crypto_generichash(namehash.data(), namehash.size(), reinterpret_cast<const unsigned char*>(name.data()), name.size(), nullptr, 0);
  crypto_generichash(derivedKey.data(), derivedKey.size(), reinterpret_cast<const unsigned char*>(name.data()), name.size(), namehash.data(), namehash.size());
  std::array<uint8_t, 32> result{};
  if (crypto_aead_xchacha20poly1305_ietf_decrypt(
        result.data(),
        nullptr,
        nullptr,
        reinterpret_cast<const unsigned char*>(ciphertext.data()),
        ciphertext.size(),
        nullptr,
        0,
        reinterpret_cast<const unsigned char*>(nounce.data()),
        derivedKey.data())
      == -1)
  {
    return {};
  }
  return result;
}


struct Connection
{

  Connection(uv_stream_t * stream) :
    m_LMQ(static_cast<LMQ*>(stream->data))
  {
    m_Handle.data = this;
    m_Wakeup.data = this;
    uv_tcp_init(stream->loop, &m_Handle);
    uv_async_init(stream->loop, &m_Wakeup, &Wakeup);
  }

  uv_stream_t * Handle()
  {
    return (uv_stream_t*)&m_Handle;
  }

  void
  Close()
  {
    uv_close((uv_handle_t*)&m_Wakeup,
             [](uv_handle_t * h)
             {
               auto self = static_cast<Connection*>(h->data);
               uv_close((uv_handle_t*)self->Handle(),
                        [](uv_handle_t * h) { delete static_cast<Connection*>(h->data); });
             });
  }

  static void
  Wakeup(uv_async_t * handle)
  {
    auto self = static_cast<Connection*>(handle->data);
    self->WriteReply();
  }

  static void
  Alloc(uv_handle_t * handle, size_t, uv_buf_t * buf)
  {
    auto self = static_cast<Connection*>(handle->data);
    *buf = uv_buf_init(self->m_ReadBuf.data(), self->m_ReadBuf.size());
  }
  
  static void
  OnRead(uv_stream_t * handle, ssize_t nread, const uv_buf_t * buf)
  {
    auto self = static_cast<Connection*>(handle->data);
    self->HandleRead(nread, buf);
  };

  void
  SendReply()
  {
    uv_async_send(&m_Wakeup);
  }
  
  void
  HandleRead(ssize_t nread, const uv_buf_t * buf)
  {
    // drop any additional stuff
    if(m_GotRequest)
      return;
    // short read
    if(nread <= 2)
    {
      Close();
      return;
    }
    m_GotRequest = true;

    std::array<unsigned char, 32> namehash{};
    const std::string name(buf->base, nread - 2);
    crypto_generichash(namehash.data(), namehash.size(), reinterpret_cast<const unsigned char*>(name.data()), name.size(), nullptr, 0);
    
    const nlohmann::json params{{"types", {2,0,}}, {"name_hash", lokimq::to_base64(namehash.begin(), namehash.end())}};
    const nlohmann::json req{{"entries", {params,}}};
    m_LMQ->lmq.request(
      m_LMQ->conn,
      "rpc.lns_names_to_owners",
      [&, name, namehash](bool success, std::vector<std::string> data)
      {
        if((not success) or data.size() < 2)
        {
          m_WriteBuf << "; cannot find info on " << name;
          SendReply();
          return;
        }
        try
        {
          size_t n = 0;
          const auto j = nlohmann::json::parse(data[1]);
          
          if(j.find("entries") == j.end())
          {
            m_WriteBuf << "; no results for " << name;
          }
          else
          {
            constexpr auto permit_key = [](std::string k) { return k != "encrypted_value" and k != "entry_index"; };
            for(const auto & item : j["entries"])
            {
              std::string encrypted;
              LNSType type = eTypeUnknown;
              m_WriteBuf << "; entry " << n++ << " for " << name << std::endl;
              for(const auto & [key, value] : item.items())
              {
                if(key == "type")
                {
                  if(not value.is_number())
                  {
                    continue;
                  }
                  switch(value.get<int>())
                  {
                  case eTypeSession:
                    type = eTypeSession;
                    m_WriteBuf << "type: session" << std::endl;
                    break;
                  case eTypeLokinet:
                    type = eTypeLokinet;
                    m_WriteBuf << "type: lokinet" << std::endl;
                    break;
                  default:
                    m_WriteBuf << "type: " << value << std::endl;
                    break;
                  }
                }
                else if(permit_key(key))
                {
                  m_WriteBuf << key << ": ";
                  if(value.is_string())
                    m_WriteBuf << value.get<std::string>();
                  else
                    m_WriteBuf << value;
                  m_WriteBuf << std::endl;
                }
                else if(key == "encrypted_value")
                {
                  encrypted = value.get<std::string>();
                }
              }
              const auto maybe = getAddress(lokimq::to_hex(namehash.begin(), namehash.end()), name, type);
              if(maybe.has_value())
              {
                m_WriteBuf << "current-address: ";
                switch(type)
                {
                case eTypeSession:
                  m_WriteBuf << "05" << lokimq::to_hex(maybe->begin(), maybe->end()) << std::endl;
                  break;
                case eTypeLokinet:
                  m_WriteBuf << lokimq::to_base32z(maybe->begin(), maybe->end()) << ".loki" << std::endl;
                  break;
                default:
                  m_WriteBuf << lokimq::to_base64(maybe->begin(), maybe->end()) << std::endl;
                  break;
                } 
              }
              else if(type == eTypeSession and not encrypted.empty())
              {
                m_WriteBuf << "encrypted-value: " << encrypted;
              }
              m_WriteBuf << std::endl;
            }
          }
        }
        catch(std::exception & ex)
        {
          m_WriteBuf << "; exception thrown while parsing response: ";
          m_WriteBuf << ex.what();
        }
        SendReply();
      }, req.dump());
  }

  std::optional<std::array<uint8_t, 32>>
  getAddress(std::string namehash, std::string name, LNSType type)
  {
    if(type == eTypeUnknown)
      return std::nullopt;
    const nlohmann::json req{{"type", type}, {"name_hash", namehash}};

    std::promise<std::optional<std::array<uint8_t, 32>>> result;
    m_LMQ->lmq.request(
      m_LMQ->conn,
      "rpc.lns_resolve",
      [&result, name, type](bool success, std::vector<std::string> data)
      {
        if(not success)
          result.set_value(std::nullopt);
        else
        {
          try
          {
            const auto j = nlohmann::json::parse(data[1]);
            const auto itr = j.find("nonce");
            if(itr == j.end())
            {
              result.set_value(std::nullopt);
            }
            else
            {
              const auto value_itr = j.find("encrypted_value");
              if(value_itr == j.end())
              {
                result.set_value(std::nullopt);
              }
              else
                result.set_value(decrypt_value(value_itr->get<std::string>(), itr->get<std::string>(), name, type));
            }
          }
          catch(...)
          {
            result.set_value(std::nullopt);
          }
        }
      }, req.dump());
    auto ftr = result.get_future();
    return ftr.get();
  }

  static void
  OnWrite(uv_write_t * req, int)
  {
    static_cast<Connection *>(req->data)->Close();
  }
  
  void
  WriteReply()
  {
    m_Reply = m_WriteBuf.str();
    m_Response.data = this;
    uv_buf_t buf = uv_buf_init(m_Reply.data(), m_Reply.size());
    uv_write(&m_Response, Handle(), &buf, 1, &OnWrite);
  }
  
  uv_tcp_t m_Handle;
  uv_async_t m_Wakeup;
  LMQ * const m_LMQ;
  uv_write_t m_Response;
  std::array<char, 256> m_ReadBuf;
  std::stringstream m_WriteBuf;
  std::string m_Reply;
  bool m_GotRequest = false;
};

static void
Accept(uv_stream_t * stream, int status)
{
  if(status)
  {
    std::cerr << "accept(): " << uv_strerror(status) << std::endl;
    return;
  }
  auto conn = new Connection(stream);
  status = uv_accept(stream, conn->Handle());
  if(status)
  {
    conn->Close();
    std::cerr << "accept(): " << uv_strerror(status) << std::endl;
    return;
  }
  uv_read_start(conn->Handle(), &Connection::Alloc, &Connection::OnRead);
}

static void
OnBindResolved(uv_getaddrinfo_t * req, int status, addrinfo * info)
{
  if(status)
  {
    std::cerr << "getaddrinfo() " << uv_strerror(status) << std::endl;
    exit(1);
  }
  else
  {
    uv_tcp_t * tcp = static_cast<uv_tcp_t*>(req->data);
    addrinfo * next = info;
    
    const sockaddr * addr = nullptr;
    do
    {
      if(next->ai_family == AF_INET)
        addr = ((const sockaddr*)next->ai_addr);
      next = next->ai_next;
    } while(next);
    if(addr == nullptr)
    {
      std::cerr << "no such address" << std::endl;
      exit(1);
    }
    status = uv_tcp_bind(tcp, addr, 0);
    if(status)
    {
      std::cerr << "uv_tcp_bind() " << uv_strerror(status) << std::endl;
      exit(1);
    }
    else
    {
      status = uv_listen((uv_stream_t*)tcp, 5, &Accept);
      if(status)
      {
        std::cerr << "uv_listen() " << uv_strerror(status) << std::endl;
        exit(1);
      }
    }
  }
  uv_freeaddrinfo(info);
}

int printhelp(std::string exe)
{
  std::cout << "usage: " << exe << " -[h|v] [-r rpcurl | -p bindport | -H bindhost]" << std::endl;
  return 0;
}


int main(int argc, char * argv[])
{

  std::string rpc = "tcp://127.0.0.1:22023";
  bool verbose = false;
  std::string bindport = "whois";
  std::string bindhost = "localhost.loki";
  int opt;
  while((opt = ::getopt(argc, argv, "hvr:p:H:")) != -1)
  {
    switch(opt)
    {
    case 'h':
      return printhelp(argv[0]);
    case 'v':
      verbose = true;
      break;
    case 'r':
      rpc = optarg;
      break;
    case 'p':
      bindport = optarg;
      break;
    case 'H':
      bindhost = optarg;
      break;
    }
  }
  LMQ lmq(rpc);
  auto loop = uv_default_loop();
  uv_getaddrinfo_t req;
  uv_tcp_t server;
  server.data = &lmq;
  uv_tcp_init(loop, &server);
  req.data = &server;
  signal(SIGINT, [](auto) { exit(0); });
  signal(SIGTERM, [](auto) { exit(0); });
  std::cout << "loki-whois " << bindhost << ":" << bindport << std::endl;
  const addrinfo hints = {0, AF_INET, SOCK_STREAM, 0,0,0,0};
  uv_getaddrinfo(loop, &req, &OnBindResolved, bindhost.c_str(), bindport.c_str(), &hints);
  return uv_run(loop, UV_RUN_DEFAULT);
}
