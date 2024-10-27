import time
import pytest
import tempfile
from dataclasses import dataclass
from pexpect import spawn, TIMEOUT, EOF
from contextlib import contextmanager
from typing import Iterator

PASSWORD = "alpine"
TIMEOUT_SECONDS = 5

@dataclass
class Forkless:
    subp: spawn
    address: str
    port: int

@pytest.fixture()
def forkless() -> Iterator[Forkless]:
    port = 2222
    with spawn(f"./forkless {port}", timeout=TIMEOUT_SECONDS) as p: 
        assert p.expect([TIMEOUT, ".* Not backgrounding"])
        yield Forkless(p, 'localhost', port)

@contextmanager
def ssh(port: int, command: str | None = None, exe="ssh") -> Iterator[spawn]:
    
    if command:
        command = " " + command
    else:
        command = ""
    portarg = "-p"
    localhost = " localhost"
    if exe == "scp":
        portarg = "-O -P"
        localhost = ""
    
    command = f"{exe} -q -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null -oPubkeyAuthentication=no {portarg} {port}{localhost}" + command
    
    fname = tempfile.mktemp()

    with open(fname, "wb") as outw:
        with spawn(command, timeout=TIMEOUT_SECONDS, logfile=outw) as p:
            try:
                p.expect([TIMEOUT, "[Pp]assword: "])
                p.sendline(PASSWORD)
                yield p
            finally:
                with open(fname, "r") as outr:
                    stdout = outr.read()
                print(f"$ {command}")
                print(stdout)

@pytest.fixture
def sshi(forkless: Forkless) -> Iterator[spawn]:
    with ssh(forkless.port) as p:
        p.expect(["# ", r"\$ "])
        yield p

def test_running(forkless: Forkless):
    pass

def test_connect_echo(forkless: Forkless):
    with ssh(forkless.port, "echo hello") as p:
        p.expect("hello")
        p.expect(EOF)
        assert 0 == p.wait()

def test_scp(forkless: Forkless):
    f1 = tempfile.mktemp()
    f2 = tempfile.mktemp()
    with open(f1, "w") as w:
        w.write("hello")
    
    with ssh(forkless.port, f"localhost:{f1} {f2}", exe="scp") as p:
        p.expect(EOF)
        assert 0 == p.wait()

    with open(f2, "r") as r:
        assert "hello" == r.read()
    
def test_interactive(sshi: spawn):
    sshi.sendline("echo hello")
    sshi.expect("hello")

def test_chukus(sshi: spawn):
    sshi.sendline("echo `echo hel``echo lo`")
    sshi.expect("hello")

def test_sigint(sshi: spawn):
    sshi.sendline("scp -f")
    with pytest.raises(TIMEOUT):
        sshi.expect(["# ", r"\$ "])
    sshi.sendintr()
    sshi.expect(["# ", r"\$ "])
    