# ⚡ lazynmap ⚡

Tired of memorizing cryptic nmap flags? 😴 Say goodbye to the command-line struggle and hello to `lazynmap`! 🎉

![lazynmap_ui](./assets/lazynmap.png)

`lazynmap` is a slick terminal user interface that transforms nmap command creation into a breeze. Craft the perfect scan command without ever leaving the comfort of our intuitive UI. 🚀

## 🔥 Features 🔥

- **Interactive UI:** Build nmap commands visually and interactively. No more endless man page scrolling! 📜
- **Comprehensive Options:** We've got all the nmap scan options covered:
  - 🎯 Target Specification
  - 🕵️ Host Discovery
  - 📡 Scan Techniques
  - 🚪 Port Specification
  - 🔬 Service Detection
  - 💻 OS Detection
  - ⏱️ Timing and Performance
  - 👻 Evasion and Spoofing
  - 📄 Output
  - ✨ Miscellaneous
  - 📜 NSE Scripts
- **Live Command Preview:** See the nmap command being built in real-time as you select options. command is displayed and can be easily copied. ✂️
- **Direct Execution:** Execute the command directly from the app! `lazynmap` will even let you know if `sudo` privileges are needed. 🛡️
- **Keyboard Warrior Friendly:** Navigate the entire UI with your keyboard. ⌨️
  - **`j` / `Down`**: Next section
  - **`k` / `Up`**: Previous section
  - **`l` / `Right`**: Next flag
  - **`h` / `Left`**: Previous flag
  - **`Space`**: Toggle/Select option
  - **`Enter`**: Edit value
  - **`c`**: Clear/Reset value
  - **`x`**: Execute command
  - **`q`**: Quit
- **Input Validation:** `lazynmap` ensures that the values you enter are valid for each nmap flag, so you can avoid common mistakes. ✅

## 🛠️ Installation 🛠️

1.  Make sure you have Rust and Cargo installed on your system. 🦀
2.  Clone this repository: `git clone https://github.com/your-username/lazynmap.git`
3.  Navigate into the project directory: `cd lazynmap`
4.  Build the project for release: `cargo build --release`
5.  The executable will be waiting for you at `target/release/lazynmap`.

## 🚀 Usage 🚀

Simply run the application from your terminal:

```bash
./target/release/lazynmap
```

The awesome `lazynmap` terminal interface will fire up, ready for you to craft your nmap commands with ease!

## 📜 License 📜

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for the full details.
