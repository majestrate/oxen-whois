#include <uv.h>
#include <lokimq/lokimq.h>
#include <lokimq/hex.h>
#include <sodium/crypto_generichash.h>
#include <nlohmann/json.hpp>
#include <getopt.h>


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
    const nlohmann::json req{{"type", 2}, {"name_hash", lokimq::to_hex(namehash.begin(), namehash.end())}};
     
    m_LMQ->lmq.request(
      m_LMQ->conn,
      "rpc.lns_resolve",
      [&, name](bool success, std::vector<std::string> data)
      {
        if((not success) or data.size() < 2)
        {
          m_WriteBuf << "; cannot find info on " << name;
          uv_async_send(&m_Wakeup);
          return;
        }
        try
        {
          const auto j = nlohmann::json::parse(data[1]);
          for(const auto & [key, value] : j.items())
          {
            m_WriteBuf << key << ": " << value << std::endl;
          }
        }
        catch(std::exception & ex)
        {
          m_WriteBuf << "; exception thrown while parsing response: ";
          m_WriteBuf << ex.what();
        }
        uv_async_send(&m_Wakeup);
      });
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
  std::cout << "loki-whois " << bindhost << ":" << bindport << std::endl;
  const addrinfo hints = {0, AF_INET, SOCK_STREAM, 0,0,0,0};
  uv_getaddrinfo(loop, &req, &OnBindResolved, bindhost.c_str(), bindport.c_str(), &hints);
  return uv_run(loop, UV_RUN_DEFAULT);
}
