int __cdecl main(int argc, const char **argv, const char **envp)
{
  init(argc, argv, envp);
  vuln();
  return 0;
}

unsigned int init()
{
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);
  return alarm(0x3Cu);
}

int vuln()
{
  char v1[112]; // [rsp+0h] [rbp-70h] BYREF

  gets(v1);
  close(1);
  return close(2);
}
