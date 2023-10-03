# Shebang

The shebang line is always at the top of each script and always starts with "#!". This line contains the path to the specified interpreter (/bin/bash) with which the script is executed. We can also use Shebang to define other interpreters like Python, Perl, and others.

- #!/bin/bash



# Conditional Execution


### Pseudo-Code
~~~
if [ the number of given arguments equals 0 ]
then
	Print: "You need to specify the var1."
	Print: "something"
	Print: "Usage:"
	Print: "   <name of the script> var1"
	Exit the script with an error
else
	The var1 variable serves as the alias for the given argument 
finish the if-condition
~~~


By default, an If-Else condition can contain only a single "If", as shown in the next example.

~~~

#!/bin/bash

value=$1

if [ $value -gt "10" ]
then
        echo "Given argument is greater than 10."
fi
~~~

### If-Elif-Else.sh

~~~
#!/bin/bash

value=$1

if [ $value -gt "10" ]
then
	echo "Given argument is greater than 10."
elif [ $value -lt "10" ]
then
	echo "Given argument is less than 10."
else
	echo "Given argument is not a number."
fi

# Here we define another condition (elif [<condition>];then) that prints a line telling us (echo -e "...") that we have given more than one argument and exits the program with an error (exit 1).
~~~


# Arguments

The advantage of bash scripts is that we can always pass up to 9 arguments (\$0-\$9) to the script without assigning them to variables or setting the corresponding requirements for these. 9 arguments because the first argument \$0 is reserved for the script. As we can see here, we need the dollar sign ($) before the name of the variable to use it at the specified position. 
# Special Variables
Special variables use the Internal Field Separator (IFS) to identify when an argument ends and the next begins. Bash provides various special variables that assist while scripting. Some of these variables are:

- $# 	This variable holds the number of arguments passed to the script.
- $@ 	This variable can be used to retrieve the list of command-line arguments.
- $n 	Each command-line argument can be selectively retrieved using its position. For example, the first argument is found at $1.
- \$$ 	The process ID of the currently executing process.
- $? 	The exit status of the script. This variable is useful to determine a command's success. The value 0 represents successful execution, while 1 is a result of a failure.

# Variables


 The assignment of variables takes place without the dollar sign ($). The dollar sign is only intended to allow this variable's corresponding value to be used in other code sections. When assigning variables, there must be no spaces between the names and values.

 In contrast to other programming languages, there is no direct differentiation and recognition between the types of variables in Bash like "strings," "integers," and "boolean." All contents of the variables are treated as string characters. Bash enables arithmetic functions depending on whether only numbers are assigned or not. It is important to note when declaring variables that they do not contain a space. Otherwise, the actual variable name will be interpreted as an internal function or a command.

 ### Declaring a Variable - Error

 ```
$ variable = "this will result with an error."

command not found: variable
 ```

# Arrays

There is also the possibility of assigning several values to a single variable in Bash. This can be beneficial if we want to scan multiple domains or IP addresses. These variables are called arrays that we can use to store and process an ordered sequence of specific type values. Arrays identify each stored entry with an index starting with 0. When we want to assign a value to an array component, we do so in the same way as with standard shell variables. All we do is specify the field index enclosed in square brackets. The declaration for arrays looks like this in Bash:
```
#!/bin/bash

domains=(www.inlanefreight.com ftp.inlanefreight.com vpn.inlanefreight.com www2.inlanefreight.com)

echo ${domains[0]}

```

We can also retrieve them individually using the index using the variable with the corresponding index in curly brackets. Curly brackets are used for variable expansion.

It is important to note that single quotes (' ... ') and double quotes (" ... ") prevent the separation by a space of the individual values in the array. This means that all spaces between the single and double quotes are ignored and handled as a single value assigned to the array.

```
#!/bin/bash

domains=("www.inlanefreight.com ftp.inlanefreight.com vpn.inlanefreight.com" www2.inlanefreight.com)
echo ${domains[0]}


$ ./Arrays.sh

www.inlanefreight.com ftp.inlanefreight.com vpn.inlanefreight.com

```

# Comparison Operators

To compare specific values with each other, we need elements that are called comparison operators. The comparison operators are used to determine how the defined values will be compared. For these operators, we differentiate between:


-    string operators
-    integer operators
-    file operators
-    boolean operators


### String Operators

- == 	is equal to
- != 	is not equal to
- < 	is less than in ASCII alphabetical order
- \> 	is greater than in ASCII alphabetical order
- -z 	if the string is empty (null)
- -n 	if the string is not null




It is important to note here that we put the variable for the given argument ($1) in double-quotes ("$1"). This tells Bash that the content of the variable should be handled as a string. Otherwise, we would get an error.


```
if [ "$1" != "HackTheBox" ]
```

String comparison operators "< / >" works only within the double square brackets [[ <condition> ]]

# Integer Operators

Comparing integer numbers can be very useful for us if we know what values we want to compare. Accordingly, we define the next steps and commands how the script should handle the corresponding value.

| Operator      | Description | 
| :---        |    :----:   |
| -eq      | is equal to     | 
| -ne   |    is not equal to      | 
|-lt 	|is less than |
| -le 	|is less than or equal to
| -gt 	|is greater than
| -ge 	|is greater than or equal to


```
#!/bin/bash

# Check the given arguments
if [ $# -lt 1 ]
then
	echo -e "Number of given arguments is less than 1"
	exit 1

elif [ $# -gt 1 ]
then
	echo -e "Number of given arguments is greater than 1"
	exit 1

else
	domain=$1
	echo -e "Number of given arguments equals 1"
fi

```


# File Operators

| Operator |                       Description                      |
|:--------:|:------------------------------------------------------:|
| -e       | if the file exist                                      |
| -f       | tests if it is a file                                  |
| -d       | tests if it is a directory                             |
| -L       | tests if it is if a symbolic link                      |
| -N       | checks if the file was modified after it was last read |
| -O       | if the current user owns the file                      |
| -G       | if the file’s group id matches the current user’s      |
| -s       | tests if the file has a size greater than 0            |
| -r       | tests if the file has read permission                  |
| -w       | tests if the file has write permission                 |
| -x       | tests if the file has execute permission               |


```
#!/bin/bash

# Check if the specified file exists
if [ -e "$1" ]
then
	echo -e "The file exists."
	exit 0

else
	echo -e "The file does not exist."
	exit 2
fi

```


# Boolean and Logical Operators

We get a boolean value "false" or "true" as a result with logical operators. Bash gives us the possibility to compare strings by using double square brackets [[ <condition> ]]. To get these boolean values, we can use the string operators. Whether the comparison matches or not, we get the boolean value "false" or "true".

```
#!/bin/bash

# Check the boolean value
if [[ -z $1 ]]
then
	echo -e "Boolean value: True (is null)"
	exit 1

elif [[ $# > 1 ]]
then
	echo -e "Boolean value: True (is greater than)"
	exit 1

else
	domain=$1
	echo -e "Boolean value: False (is equal to)"
fi

```

# Logical Operators

With logical operators, we can define several conditions within one. This means that all the conditions we define must match before the corresponding code can be executed.

|Operator |	Description|
|---------|------------|
|! 	|logical negotation NOT|
|&& |	logical AND|
| \|\| 	|logical OR|

```
#!/bin/bash

# Check if the specified file exists and if we have read permissions
if [[ -e "$1" && -r "$1" ]]
then
	echo -e "We can read the file that has been specified."
	exit 0

elif [[ ! -e "$1" ]]
then
	echo -e "The specified file does not exist."
	exit 2

elif [[ -e "$1" && ! -r "$1" ]]
then
	echo -e "We don't have read permission for this file."
	exit 1

else
	echo -e "Error occured."
	exit 5
fi
```


# Arithmetic

### Arithmetic Operators
|Operator |	Description|
|---------|------|
|+ |	Addition|
|- |	Substraction|
|* 	|Multiplication|
|/ |	Division|
|% 	|Modulus|
|variable++ 	|Increase the value of the variable by 1|
|variable-- 	|Decrease the value of the variable by 1|



We can summarize all these operators in a small script:

~~~
#!/bin/bash

increase=1
decrease=1

echo "Addition: 10 + 10 = $((10 + 10))"
echo "Substraction: 10 - 10 = $((10 - 10))"
echo "Multiplication: 10 * 10 = $((10 * 10))"
echo "Division: 10 / 10 = $((10 / 10))"
echo "Modulus: 10 % 4 = $((10 % 4))"

((increase++))
echo "Increase Variable: $increase"

((decrease--))
echo "Decrease Variable: $decrease"
~~~

The output of this script looks like this:

~~~
$ ./Arithmetic.sh

Addition: 10 + 10 = 20
Substraction: 10 - 10 = 0
Multiplication: 10 * 10 = 100
Division: 10 / 10 = 1
Modulus: 10 % 4 = 2
Increase Variable: 2
Decrease Variable: 0
~~~


We can also calculate the length of the variable. Using this function ${#variable}, every character gets counted, and we get the total number of characters in the variable.

~~~
#!/bin/bash

htb="HackTheBox"

echo ${#htb}
~~~

```
$ ./VarLength.sh

10
```


# Input Control

```
# Available options
<SNIP>
echo -e "Additional options available:"
echo -e "\t1) Identify the corresponding network range of target domain."
echo -e "\t2) Ping discovered hosts."
echo -e "\t3) All checks."
echo -e "\t*) Exit.\n"

read -p "Select your option: " opt

case $opt in
	"1") network_range ;;
	"2") ping_host ;;
	"3") network_range && ping_host ;;
	"*") exit 0 ;;
esac

```
The first echo lines serve as a display menu for the options available to us. With the read command, the line with "Select your option:" is displayed, and the additional option -p ensures that our input remains on the same line. Our input is stored in the variable opt, which we then use to execute the corresponding functions with the case statement, which we will look at later. Depending on the number we enter, the case statement determines which functions are executed.


# Output Control

. If our scripts become more complicated later, they can take much more time than just a few seconds. To avoid sitting inactively and waiting for our script's results, we can use the tee utility. It ensures that we see the results we get immediately and that they are stored in the corresponding files.


```
# Identify Network range for the specified IP address(es)
function network_range {
	for ip in $ipaddr
	do
		netrange=$(whois $ip | grep "NetRange\|CIDR" | tee -a CIDR.txt)
		cidr=$(whois $ip | grep "CIDR" | awk '{print $2}')
		cidr_ips=$(prips $cidr)
		echo -e "\nNetRange for $ip:"
		echo -e "$netrange"
	done
}

<SNIP>

# Identify IP address of the specified domain
hosts=$(host $domain | grep "has address" | cut -d" " -f4 | tee discovered_hosts.txt)

<SNIP>

```

When using tee, we transfer the received output and use the pipe (|) to forward it to tee. The "-a / --append" parameter ensures that the specified file is not overwritten but supplemented with the new results. At the same time, it shows us the results and how they will be found in the file.


# Flow Control - Loops

 Each control structure is either a branch or a loop. Logical expressions of boolean values usually control the execution of a control structure. These control structures include:

-    Branches:
        - If-Else Conditions
        - Case Statements

-    Loops:
        - For Loops
        - While Loops
        - Until Loops


### For Loops

The For loop is executed on each pass for precisely one parameter, which the shell takes from a list, calculates from an increment, or takes from another data source. The for loop runs as long as it finds corresponding data. This type of loop can be structured and defined in different ways. For example, the for loops are often used when we need to work with many different values from an array. This can be used to scan different hosts or ports. We can also use it to execute specific commands for known ports and their services to speed up our enumeration process.

```
for variable in 1 2 3 4
do
	echo $variable
done
```

```
for variable in file1 file2 file3
do
	echo $variable
done
```
```
for ip in "10.10.10.170 10.10.10.174 10.10.10.175"
do
	ping -c 1 $ip
done
```


```
#oneliners
$ for ip in 10.10.10.170 10.10.10.174;do ping -c 1 $ip;done
```

### While Loops

The while loop is conceptually simple and follows the following principle:

- A statement is executed as long as a condition is fulfilled (true).

The while loops also work with conditions like if-else. A while loop needs some sort of a counter to orientate itself when it has to stop executing the commands it contains. Otherwise, this leads to an endless loop. Such a counter can be a variable that we have declared with a specific value or a boolean value. While loops run while the boolean value is "True". Besides the counter, we can also use the command "break," which interrupts the loop when reaching this command like in the following example:

```
#!/bin/bash

counter=0

while [ $counter -lt 10 ]
do
  # Increase $counter by 1
  ((counter++))
  echo "Counter: $counter"

  if [ $counter == 2 ]
  then
    continue
  elif [ $counter == 4 ]
  then
    break
  fi
done
```

```
$ ./WhileBreaker.sh

Counter: 1
Counter: 2
Counter: 3
Counter: 4
```

# Case Statements

Case statements are also known as switch-case statements in other languages, such as C/C++ and C#. The main difference between if-else and switch-case is that if-else constructs allow us to check any boolean expression, while switch-case always compares only the variable with the exact value.

```
case <expression> in
	pattern_1 ) statements ;;
	pattern_2 ) statements ;;
	pattern_3 ) statements ;;
esac
```

The definition of switch-case starts with case, followed by the variable or value as an expression, which is then compared in the pattern. If the variable or value matches the expression, then the statements are executed after the parenthesis and ended with a double semicolon (;;).

```
<SNIP>
# Available options
echo -e "Additional options available:"
echo -e "\t1) Identify the corresponding network range of target domain."
echo -e "\t2) Ping discovered hosts."
echo -e "\t3) All checks."
echo -e "\t*) Exit.\n"

read -p "Select your option: " opt

case $opt in
	"1") network_range ;;
	"2") ping_host ;;
	"3") network_range && ping_host ;;
	"*") exit 0 ;;
esac
<SNIP>
```

# Functions

We combine several commands in a block between curly brackets ( { ... } ) and call them with a function name defined by us with functions. Once a function has been defined, it can be called and used again during the script.

It is important to note that functions must always be defined logically before the first call since a script is also processed from top to bottom. Therefore the definition of a function is always at the beginning of the script. There are two methods to define the functions:

- Method 1
```
function name {
	<commands>
}
```

- Method 2

```
name() {
	<commands>
}
```

### Parameter Passing

Such functions should be designed so that they can be used with a fixed structure of the values or at least only with a fixed format. In principle, the same applies to the passed parameters as to parameters passed to a shell script. These are $1 - $9 (${n}), or $variable. Each function has its own set of parameters. So they do not collide with those of other functions or the parameters of the shell script.

An important difference between bash scripts and other programming languages is that all defined variables are always processed globally unless otherwise declared by "local."
```
#!/bin/bash

function print_pars {
	echo $1 $2 $3
}

one="First parameter"
two="Second parameter"
three="Third parameter"

print_pars "$one" "$two" "$three"
```

### Return Values


When we start a new process, each child process (for example, a function in the executed script) returns a return code to the parent process (bash shell through which we executed the script) at its termination, informing it of the status of the execution. This information is used to determine whether the process ran successfully or whether specific errors occurred. Based on this information, the parent process can decide on further program flow.


|Return Code 	|Description|
|--------|----------|
|1 	|General errors|
|2 	|Misuse of shell builtins|
|126 	|Command invoked cannot execute|
|127 	|Command not found|
|128 	|Invalid argument to exit|
|128+n 	|Fatal error signal "n"|
|130 	|Script terminated by Control-C|
|255\* 	|Exit status out of range|


To get the value of a function back, we can use several methods like return, echo, or a variable. In the next example, we will see how to use "$?" to read the "return code," how to pass the arguments to the function and how to assign the result to a variable.

- Return.sh

```
#!/bin/bash

function given_args {

        if [ $# -lt 1 ]
        then
                echo -e "Number of arguments: $#"
                return 1
        else
                echo -e "Number of arguments: $#"
                return 0
        fi
}

# No arguments given
given_args
echo -e "Function status code: $?\n"

# One argument given
given_args "argument"
echo -e "Function status code: $?\n"

# Pass the results of the funtion into a variable
content=$(given_args "argument")

echo -e "Content of the variable: \n\t$content"
```


# Debugging

Bash allows us to debug our code by using the "-x" (xtrace) and "-v" options. 

```
$ bash -x script.sh
```

