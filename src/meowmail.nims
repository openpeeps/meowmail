when defined(macosx):
  --passL:"/opt/local/lib/libssl.a"
  --passL:"/opt/local/lib/libcrypto.a"
  --passL:"/opt/local/lib/libevent.a"
  # --passL:"/opt/local/lib/libgmime.a"
  --passC:"-I /opt/local/include"
elif defined(linux):
  --passL:"/usr/local/lib/libssl.so"
  --passL:"/usr/local/lib/libcrypto.so"
  --passL:"/usr/local/lib/libevent.a"
  # --passL:"/usr/local/lib/libgmime.a"
  --passC:"-I /usr/local/include"
