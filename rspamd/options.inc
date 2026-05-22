dns {
  nameserver = ["unbound"];
  timeout = 1s;
  sockets = 16;
}
