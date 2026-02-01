# Ptrace-based Library Injection 💉 (my first personal project at Worri coffe XD)

> *"Why ask for permission when you can just... inject?"*

## Why I make this?

- I want to improve my understanding on some injection techniques ( **ptrace** is a good reason to learn & start). Besides, I could enhance my coding skills as well.

- Furthermore, hopefully after this simple project, I could contribute (or create?!?) something to **modify Frida for stealthy evasion against some detection mechanisms**, or even make something crazier!
- Contact me if you have the same sense of purpose ;)

## 📁 Files

| File | Description |
|------|-------------|
| `injector.c` | Attaches to target, allocates memory, injects library |
| `hook.c` | Payload library that hooks `fopen()` (for example) |
| `running_process.c` | Test target process |

## 🛠️ Build & Run

```bash
# Compile everything
gcc -o injector injector.c -ldl
gcc -shared -fPIC -o libfopenhook.so hook.c -ldl
gcc -o running_process running_process.c

# Run target, then inject
./running_process &
sudo ./injector <PID> /full/path/to/libfopenhook.so
```

## ⚠️ Disclaimer

Educational purposes only.

---
*Built with curiosity and coffee* ☕
