when defined(macosx):
  --passC:"-DHAVE_NS_TYPE=1 -DHAVE_DECL_NS_T_INVALID=1"
  --passC:"-I/opt/local/include"
  --passL:"-Wl,-rpath,/opt/local/lib -L/opt/local/lib -lssl -lcrypto -lopendmarc"
  --passL:"-L/usr/local/lib -lspf2"
  --passC:"-I/usr/local/include/spf2"
elif defined(linux):
  --passC:"-I/usr/include"
  --passC:"-I/usr/include/spf2"
  --passL:"-L/usr/lib/x86_64-linux-gnu -lspf2"
  --passL:"-L/usr/local/lib/lib -L/usr/local/lib -Wl,-rpath,/usr/local/lib/lib -Wl,-rpath,/usr/local/lib -lssl -lcrypto -lopendmarc"
