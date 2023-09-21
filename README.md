# CrackEverything6
Crack Everything for CrackMapExec version 6

To run against a single host

```
python ~/Tools/CrackEverything6.py -r <RHOST> -u <USERNAME> -p <PASSWORD> -d <DOMAIN NAME>
```

To run against a hosts file

```
python ~/Tools/CrackEverything6.py -F <FILE NAME> -u <USERNAME> -p <PASSWORD> -d <DOMAIN NAME>
```

To run when your cme.conf file has a different prompt than Pwn3d!

```
python ~/Tools/CrackEverything6.py -r <RHOST> -u <USERNAME> -p <PASSWORD> -d <DOMAIN NAME> -Z <PROMPT>
```

To run with impacket

```
python ~/Tools/CrackEverything6.py -r <RHOST> -u <USERNAME> -p <PASSWORD> -d <DOMAIN NAME> -I 
```

To run with hashes

```
python ~/Tools/CrackEverything6.py -r <RHOST> -u <USERNAME> -H <HASH> -d <DOMAIN NAME>
```

To run against multiple usernames or passwords or both

```
python ~/Tools/CrackEverything6.py -r <RHOST> -u <USERNAME FILE> -p <PASSWORD FILE> -d <DOMAIN NAME>
```

To run everything at once

```
python ~/Tools/CrackEverything6.py -r <RHOST> -u <USERNAME> -p <PASSWORD> -d <DOMAIN NAME> -I -Z <PROMPT>
```

