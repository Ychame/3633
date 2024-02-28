int __cdecl main(int argc, const char **argv, const char **envp)
{
  char *value; // [rsp+8h] [rbp-18h] BYREF
  FILE *stream; // [rsp+10h] [rbp-10h]
  unsigned __int64 v6; // [rsp+18h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  stream = fopen("/app/flag.txt", "r");
  value = 0LL;
  __isoc99_fscanf(stream, "%ms", &value);
  fclose(stream);
  setenv("FLAG", value, 1);
  free(value);
  setuid(0x3E8u);
  execl("/app/unsetenv", "unsetenv", 0LL);
  return 0;
}