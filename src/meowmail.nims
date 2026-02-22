when defined(macosx):
  --passL:"/opt/local/lib/libevent_openssl.a"
  --passL:"/opt/local/lib/libevent.a"
  --passL:"/opt/local/lib/libssl.a"
  --passL:"/opt/local/lib/libcrypto.a"
  --passL:"-lz"
  --passC:"-I /opt/local/include"
elif defined(linux):
  --passL:"/usr/lib/x86_64-linux-gnu/libevent_openssl.a"
  --passL:"/usr/lib/x86_64-linux-gnu/libevent.a"
  --passL:"/usr/lib/x86_64-linux-gnu/libssl.so"
  --passL:"/usr/lib/x86_64-linux-gnu/libcrypto.so"
  --passL:"-lz"
  --passC:"-I /usr/include"