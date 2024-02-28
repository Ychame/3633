int __cdecl main(int argc, const char **argv, const char **envp)
{
  char *v3; // rax
  int v6; // [rsp+Ch] [rbp-14h]
  char buf[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v8; // [rsp+18h] [rbp-8h]

  v8 = __readfsqword(0x28u);
  setbuf(stdin, 0LL);
  setbuf(_bss_start, 0LL);
  setbuf(stderr, 0LL);
  unsetenv("FLAG");
  v6 = 3;
  while ( v6-- )
  {
    printf("Enter the name of an environment variable: ");
    read(0, buf, 0x20uLL);
    v3 = getenv(buf);
    printf("The value of the environment variable %s is %s.\n", buf, v3);
  }
  puts("Enter feedback for this challenge below:");
  read(0, buf, 0x30uLL);
  puts("Thanks for your feedback!");
  return 0;
}