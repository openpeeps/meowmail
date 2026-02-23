when defined(macosx):
  # --passL:"/opt/local/lib/libevent_openssl.a"
  # --passL:"/opt/local/lib/libevent.a"
  # --passL:"/opt/local/lib/libssl.a"
  # --passL:"/opt/local/lib/libcrypto.a"
  --passC:"-I /opt/local/include"
  --passL:"-L /opt/local/lib -levent -levent_openssl -lssl -lcrypto"
elif defined(linux):
  # --passL:"/usr/lib/x86_64-linux-gnu/libevent_openssl.a"
  # --passL:"/usr/local/lib/libevent.a"
  --passC:"-I /usr/include"
  --passL:"-L/usr/local/lib/lib -L/usr/local/lib -Wl,-rpath,/usr/local/lib/lib -Wl,-rpath,/usr/local/lib -levent -levent_openssl -lssl -lcrypto"

--path:"/Users/georgelemon/Development/packages/clients/libevent/src"