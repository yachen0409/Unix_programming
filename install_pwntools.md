# Install pwntools

`pwntools` might not be mandatory for solving lab challenges, but it makes your life easier. It is a python package that allows you to interact with a remote server (or a local process) ***programmatically***. It is typically used for solving CTF challenges. You can find its document [here](https://docs.pwntools.com/en/stable/). To install `pwntools` in your environment, please select the appropriate methods listed below that matches your runtime. We use `virtualenv` package to ensure the installed packages are not mixed up with others. We assume the `pwntools` will be installed in the `~/pwntools` directory. You may choose your preferred installation directory.

- If you run our Ubuntu Linux docker on an x86_64 machine, you can install it using the commands:
    ```
    virtualenv -p python3 ~/pwntools
    . ~/pwntools/bin/activate
    pip3 install --upgrade pwntools
    ```

- If you run our Ubuntu Linux docker on an arm64 (e.g., Apple M1/M2) machine, you can install it using the commands:
    ```
    virtualenv -p python3 ~/pwntools
    . ~/pwntools/bin/activate
    pip3 install --upgrade unicorn==1.0.3 pwntools
    ```

- If you plan to run it natively on your mac (both Intel and Apple chips), you can install it using the [`homebrew`](https://brew.sh/) package manager.

    ```
    brew install pwntools
    ```
    Note that `homebrew` may be installed in `/opt/homebrew` or in `/usr/local`. Once `pwntools` is installed, you can activate its virtualenv installed by `brew` using the command (assume pwntools 4.8.0 is installed):
    ```
    . /usr/local/Cellar/pwntools/4.8.0/libexec/bin/activate
    ```
    or
    ```
    . /opt/homebrew/Cellar/pwntools/4.8.0/libexec/bin/activate
    ```
    depending on the installation directory.

To validate your installation, ensure that your `virtualenv` has been activated and type the command in `python3` interpreter: `from pwn import *`. Your installation is successful if you do not receive any error messages.

