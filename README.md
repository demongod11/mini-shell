Name :  Chandrabhsuhan Reddy Chigarapally
Roll Number : 200101027
Programming Language Used : C
Operating System Used : Linux

Method to Run:
1.Download the c file i.e., 200101027.c
2.In terminal go to the directory in which the c file is present
3.In terminal type gcc 200101027.c -o some_name
4.Now the executable some_name has been created. Now type ./some_name

Features implemented:
1.The shell accepts simple command, relative path command and also absolute path command
  
      Example:

      cs242_mini_shell > ls
      cs242_mini_shell > /bin/ls

      The above two commands work equivalently as in like the original shell works

2.Redirection has been implemented.

   Input Redirection(<), Output Redirection(>), Append(>>), Error Redirection and Multilevel Redirection has been implemented

   Example:
      
      > file
      echo hello 2147483648> file
      echo a > $NO_ENV | echo b, unset NO_ENV
      echo a > out; echo b >> out; echo c >> out; echo d >> out; cat out
      ls>a>b>c>d>e>f>g>h>i>j>k>l>m>n>o>p>q>r>s>t>u>v>w>x>y>z>A>B>C>D>E>F>G>H>I>J>K>L>M>N>O>P>Q>R>S>T>U>V>W>X>Y>Z>aa>ab>ac>ad>ae>af>ag>ah>ai>aj>ak>al>am>an>ao>ap>aq>ar>as>at>au>av>aw>ax>ay>az>aA>aB>aC>aD>aE>aF>aG>aH>aI>aJ>aK>aL>aM>aN>aO>aP>aQ>aR>aS>aT>aU>aV;ls

3.Multilevel Pipes have been implemented.

   Example:
      
      cs242_mini_shell > ls | cat
      cs242_mini_shell > ls | cat | grep README
      cs242_mini_shell > cat some_file.txt | head -n 7 | tail -n 4 | head -n 3

4.Combination of redirection and piping has also been implemented

   Here we can pipe and redirect or redirect and pipe as many times as we want in the same command line
    
   Example:

      cs242_mini_shell > ls | cat > cat.txt
      cs242_mini_shell > cat < cat.txt | grep README | wc 1> wc.txt

5.Few of the Internal Commands have also been implemented.

   List of internal commands implemented:
   1.echo

      Example:
         cs242_mini_shell > echo hello
         cs242_mini_shell > echo -n hello

   2.cd 

      All variations of cd has been implemented

      Example:
         cs242_mini_shell > cd ./dir
         cs242_mini_shell > cd /bin 
         cs242_mini_shell > cd ..
         cs242_mini_shell > cd

   3.pwd

      Example:
         cs242_mini_shell > pwd   

   4.export 

      Example:
         cs242_mini_shell > export PATH="/"  

   5.unset

      Example:
         cs242_mini_shell > unset

   6.env

      Example:
         cs242_mini_shell > env

   7.history

      Example:
         cs242_mini_shell > history      

   8.exit

      Example:
         cs242_mini_shell > exit           
   
   etc.....

6.Few of the External Commands have also been implemented.

   Example : man, which, chsh, whereis, passwd, date, cal, clear,sleep, history, apropos, exit,shutdown, Is, cat, more,less,touch, cp, mv, rm,script, find, mkdir, cd, pwd, rmdir, chmod, grep, sort etc..

7.Some environment variables are also created.

   Example: USER, TERM, SHELL, HOME, PATH, LANG, PWD



  

       



  


   
