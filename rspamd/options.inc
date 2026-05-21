dns {
  nameserver = ["unbound-server"];
  timeout = 1s;
  sockets = 16;
}
