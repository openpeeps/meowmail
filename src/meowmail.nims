when defined(macosx):
  --passC:"-I /opt/local/include"
  --passL:"-Wl,-rpath,/opt/local/lib -L/opt/local/lib -levent_openssl -levent -lssl -lcrypto"
elif defined(linux):
  # --passL:"/usr/lib/x86_64-linux-gnu/libevent_openssl.a"
  # --passL:"/usr/local/lib/libevent.a"
  --passC:"-I /usr/include"
  --passL:"-L/usr/local/lib/lib -L/usr/local/lib -Wl,-rpath,/usr/local/lib/lib -Wl,-rpath,/usr/local/lib -levent -levent_openssl -lssl -lcrypto"
