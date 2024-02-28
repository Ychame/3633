int __cdecl main(int argc, const char **argv, const char **envp)
{
  init(argc, argv, envp);
  puts("Welcome to the Game of Luck3!");
  puts(&byte_2283);
  puts("Win me to get the flag!");
  puts(&byte_2283);
  game3();
  print_flag();
  return 0;
}

unsigned int init()
{
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);
  return alarm(0xB4u);
}


__int64 game3()
{
  char s[8]; // [rsp+0h] [rbp-60h] BYREF
  __int64 v2; // [rsp+8h] [rbp-58h]
  __int64 money; // [rsp+10h] [rbp-50h]
  __int64 bet; // [rsp+18h] [rbp-48h] BYREF
  __int64 guess; // [rsp+20h] [rbp-40h] BYREF
  char v6[45]; // [rsp+2Bh] [rbp-35h] BYREF
  unsigned __int64 v7; // [rsp+58h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  *(_QWORD *)s = 0LL;
  v2 = 0LL;
  guess = 0LL;
  money = 500LL;
  bet = 500LL;
  strcpy(&v6[5], "You are cheating! Get out of here!\n");
  strcpy(v6, "Bye\n");
  do
  {
    menu3();
    __isoc99_scanf("%s", s);
    puts("");
    if ( strlen(s) > 0xF )
    {
      pretty_alert(&v6[5], 0LL);
      exit(0);
    }
  }
  while ( s[0] != 'Y' && s[0] != 'y' );
  printf("Money you have : %lld$\n", money);
  while ( 1 )
  {
    do
    {
      printf("Place a Bet : ");
      __isoc99_scanf("%lld", &bet);
      if ( bet < 0 )
      {
        pretty_alert(&v6[5], 0LL);
        exit(0);
      }
      if ( money - bet < 0 )
        puts("You don't have enough money to bet!");
    }
    while ( money - bet < 0 );
    printf("Make a Guess : ");
    __isoc99_scanf("%d", &guess);
    HIDWORD(guess) = (int)guess % 10 + 1;
    if ( (_DWORD)guess != HIDWORD(guess) )
    {
      pretty_alert(v6, 2LL);
      exit(0);
    }
    puts("Oh, you guess it!");
    money += bet;
    printf("You now have : %lld$\n", money);
    if ( money > 1000000 )
      break;
    printf("Continue? Y/N : ");
    __isoc99_scanf("%s", s);
    puts(&byte_2283);
    if ( strlen(s) > 0x64 || s[0] != 89 && s[0] != 121 )
    {
      pretty_alert(v6, 2LL);
      exit(0);
    }
  }
  return 0LL;
}

int menu3()
{
  puts("Rules of game:");
  puts("(1) You will be given 500$");
  puts("(2) Place a Bet");
  puts("(3) Guess the number what computer thinks of !");
  puts("(4) computer's number changes every new time !.");
  puts("(5) You have to guess a nubmer between 1-10");
  puts("(6) Kick you out if you gues it wrong !. !.");
  puts("(7) Dont judge my spelling or logic!");
  puts("(8) Put your mind, Win the game !..");
  puts("(9) get past $1000000 to win the flag!");
  puts("(10) Good Luck !..");
  putchar(10);
  return printf("Are you ready? Y/N : ");
}


unsigned __int64 print_flag()
{
  FILE *stream; // [rsp+8h] [rbp-118h]
  char s[264]; // [rsp+10h] [rbp-110h] BYREF
  unsigned __int64 money; // [rsp+118h] [rbp-8h]

  money = __readfsqword(0x28u);
  stream = fopen("/flag.txt", "r");
  if ( !stream )
  {
    fwrite("error reading flag!", 1uLL, 0x13uLL, stderr);
    exit(1);
  }
  fgets(s, 256, stream);
  fclose(stream);
  puts("What the... how did you get that money (even when I tried to stop you)!? I guess you beat me!");
  printf("The flag is %s\n", s);
  puts("Thant you for playing !");
  return money - __readfsqword(0x28u);
}


void __fastcall pretty_alert(__int64 a1, unsigned int a2)
{
  if ( a2 <= 4 )
  {
    switch ( (unsigned __int64)jpt_1376 + (int)jpt_1376[a2] )
    {
      case 0uLL:
        printf("\x1B[91m");
        printf((const char *)a1);
        printf("\x1B[0m");
        break;
      case 1uLL:
        printf("\x1B[92m");
        printf((const char *)a1);
        printf("\x1B[0m");
        break;
      case 2uLL:
        printf("\x1B[93m");
        printf((const char *)a1);
        printf("\x1B[0m");
        break;
      case 3uLL:
        printf("\x1B[94m");
        printf((const char *)a1);
        printf("\x1B[0m");
        break;
      case 4uLL:
        printf("\x1B[96m");
        printf((const char *)a1);
        printf("\x1B[0m");
        break;
      default:
        break;
    }
  }
  exit(0);
}