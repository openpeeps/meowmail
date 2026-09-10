switch("path", "$projectDir/../src")

# spf2/opendmarc headers + libs (same flags as src/meowmail.nims)
switch("passC", "-DHAVE_NS_TYPE=1 -DHAVE_DECL_NS_T_INVALID=1 -I/usr/local/include/spf2")
switch("passL", "-lspf2 -lopendmarc -lssl -lcrypto")
when defined(macosx):
  switch("passC", "-I/opt/local/include")
